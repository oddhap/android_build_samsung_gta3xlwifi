#!/usr/bin/env python3
"""Install the verified ARM64 recovery, with exact preimage and readback guards."""
from pathlib import Path
import argparse,hashlib,json,subprocess
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--release',type=Path,required=True);p.add_argument('--previous',type=Path);a=p.parse_args()
r=Path(__file__).resolve().parent.parent;private=r/'.private/gapps';base=private/'baseline';adb='/opt/homebrew/bin/adb';block='/dev/block/platform/13500000.dwmmc0/by-name/'
def sha(b):return hashlib.sha256(b).hexdigest()
def sh(c):return subprocess.check_output([adb,'shell',c],text=True).strip()
def read(name):return subprocess.check_output([adb,'exec-out','dd if='+block+name+' bs=4194304 2>/dev/null'])
check=json.loads((a.release/'image-check.json').read_text());assert check['build_exit_code']==0 and check['userspace_bits']==64 and check['ramdisk_bytes']<=16777216
assert check['keymaster_boot_header_patch']=='2026-10-01'
assert json.loads((a.release/'crypto-regression-check.json').read_text())['passed']
image=(a.release/'recovery-twrp-sm-t510.img').read_bytes();assert len(image)==check['file_bytes']<=47185920 and sha(image)==check['sha256'];assert image[44:48]==bytes.fromhex('aa01001c')
assert sh('id -u')=='0' and sh('getprop ro.twrp.version')=='3.7.1_12' and sh('getprop ro.product.device')=='gta3xlwifi'
backup=json.loads((private/'data-backup/data-backup.json').read_text());assert set(backup['partitions'])=={'userdata','efs'} and all(x['gzip_crc_and_length_validated'] for x in backup['partitions'].values())
for name in ['userdata','efs']:assert sh('blockdev --getro '+block+name)=='0','Backup freeze is still active'
firmware=json.loads((base/'firmware.json').read_text())['partitions'];previous=a.previous or base/'recovery.img';old=previous.read_bytes();assert len(old)==47185920
allowed=[firmware['recovery']['sha256']]
if a.previous:
 prior=json.loads((a.release/'install-check.json').read_text());assert prior['passed'];allowed.append(prior['full_partition_sha256'])
assert sha(old) in allowed and read('recovery')==old
before={name:sh('sha256sum '+block+name).split()[0] for name in ['boot','vendor','dtbo','vbmeta']};assert all(before[n]==firmware[n]['sha256'] for n in before)
sh('mkdir -p /data/gapps-staging; chmod 700 /data/gapps-staging')
for src,name,digest in [(previous,'recovery-rollback.img',sha(old)),(a.release/'recovery-twrp-sm-t510.img','recovery-candidate.img',sha(image))]:
 subprocess.run([adb,'push',str(src),'/data/gapps-staging/'+name],check=True,capture_output=True);assert sh('sha256sum /data/gapps-staging/'+name).split()[0]==digest
written=False
try:
 written=True;sh('dd if=/data/gapps-staging/recovery-candidate.img of='+block+'recovery bs=1048576 conv=fsync')
 actual=read('recovery');assert actual==image+old[len(image):],'Full recovery readback mismatch'
 assert before=={n:sh('sha256sum '+block+n).split()[0] for n in before},'Other firmware partition changed'
 result={'passed':True,'checked_at_utc':datetime.now(timezone.utc).isoformat(),'recovery_image_sha256':sha(image),'full_partition_sha256':sha(actual),'full_partition_readback_verified':True,'unused_tail_preserved':True,'other_firmware_partitions_preserved':True,'fresh_userdata_efs_backup_verified':True,'hardware_tested':False}
 (a.release/'install-check.json').write_text(json.dumps(result,indent=2)+'\n');print('ARM64 recovery installed and full readback verified.',flush=True)
except BaseException:
 if written:
  sh('dd if=/data/gapps-staging/recovery-rollback.img of='+block+'recovery bs=1048576 conv=fsync');assert read('recovery')==old
 raise
finally:sh('rm -f /data/gapps-staging/recovery-rollback.img /data/gapps-staging/recovery-candidate.img; rmdir /data/gapps-staging 2>/dev/null || true')
