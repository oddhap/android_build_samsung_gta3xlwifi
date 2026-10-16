#!/usr/bin/env python3
"""Install checked ARM64 ROM + original GApps into ARM64 TWRP, without formatting."""
import argparse,hashlib,json,re,subprocess,zipfile
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--release',type=Path,required=True);p.add_argument('--recovery',type=Path,required=True);p.add_argument('--gapps',type=Path,required=True);a=p.parse_args()
r=Path(__file__).resolve().parent.parent;private=r/'.private/gapps';adb='/opt/homebrew/bin/adb';block='/dev/block/platform/13500000.dwmmc0/by-name/'
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(8388608),b''):h.update(chunk)
 return h.hexdigest()
def sh(c):return subprocess.check_output([adb,'shell',c],text=True).strip()
def read(name):return subprocess.check_output([adb,'exec-out','dd if='+block+name+' bs=4194304 2>/dev/null'])
reports={n:json.loads((a.release/(n+'.json')).read_text()) for n in ['offline-validation','release-signature-check','gapps-headroom-check','charger-package-check','double-tap-wake-check']}
assert all(x['passed'] for x in reports.values());signature=reports['release-signature-check'];build=signature['build_incremental']
assert reports['gapps-headroom-check']['gapps_zip_unmodified'];packages=list(a.release.glob('lineage-21.0-*-arm64-privatekeys.zip'));assert len(packages)==1;ota=packages[0];assert sha(ota)==signature['rom_zip_sha256']==reports['offline-validation']['rom_zip_sha256']
gappssha='6e1c3616862ce5b33e2b96074f86ae846eb1351a26a980e1ed140f8a7e7a4fd6';assert sha(a.gapps)==gappssha
assert sh('id -u')=='0' and sh('getprop ro.twrp.version')=='3.7.1_12' and sh('getprop ro.bionic.arch')=='arm64' and sh('getprop ro.product.device')=='gta3xlwifi'
backup=json.loads((private/'data-backup/data-backup.json').read_text());assert all(x['gzip_crc_and_length_validated'] for x in backup['partitions'].values())
for item in backup['partitions'].values():assert sha(Path(item['path']))==item['gzip_sha256']
firmware=json.loads((private/'baseline/firmware.json').read_text())['partitions'];rec=json.loads((a.recovery/'install-check.json').read_text());assert rec['passed'] and hashlib.sha256(read('recovery')).hexdigest()==rec['full_partition_sha256']
for name in ['boot','vendor','dtbo','vbmeta']:
 assert sh('sha256sum '+block+name).split()[0]==firmware[name]['sha256'],name
for name in ['userdata','efs']:assert sh('blockdev --getro '+block+name)=='0'
with zipfile.ZipFile(ota) as z:
 script=z.read('META-INF/com/google/android/updater-script').decode();assert 'format(' not in script and 'delete_recursive("/data' not in script
 assert set(re.findall(r'/dev/block/platform/13500000\.dwmmc0/by-name/(\w+)',script))=={'boot','system','product','vendor'}
 boot=z.read('boot.img')
stage='/data/gapps-staging';sh('mkdir -p '+stage+'; chmod 700 '+stage)
marker='/data/gapps-storage-check';sh('dd if=/dev/urandom of='+marker+' bs=64 count=1 2>/dev/null; chmod 600 '+marker);markerhash=sh('sha256sum '+marker).split()[0]
logs=private/('install-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'));logs.mkdir(mode=0o700)
for local,remote,expected in [(ota,stage+'/rom.zip',signature['rom_zip_sha256']),(a.gapps,stage+'/gapps.zip',gappssha)]:
 subprocess.run([adb,'push',str(local),remote],check=True,capture_output=True);assert sh('sha256sum '+remote).split()[0]==expected
for service in ['keystore2','recovery-keymaster','recovery-gatekeeper','recovery-mobicore','recovery-crypto-props']:sh('stop '+service)
for mount in ['/vendor','/system_root','/product','/mnt/system']:
 if any(x.split()[1]==mount for x in sh('cat /proc/mounts').splitlines()):sh('umount '+mount)
assert not any(x.split()[1].startswith('/vendor') for x in sh('cat /proc/mounts').splitlines())
def install(remote,kind):
 previous=len(subprocess.check_output([adb,'exec-out','cat /tmp/recovery.log']))
 with (logs/(kind+'.log')).open('w') as f:result=subprocess.run([adb,'shell','twrp','install',remote],stdout=f,stderr=subprocess.STDOUT)
 subprocess.run([adb,'pull','/tmp/recovery.log',str(logs/(kind+'-recovery.log'))],check=True,capture_output=True)
 raw=(logs/(kind+'-recovery.log')).read_bytes();assert len(raw)>=previous;data=raw[previous:].decode(errors='replace')
 assert result.returncode==0,kind+' TWRP command failed'
 codes=re.findall(r'Updater process ended with (?:RC=|ERROR: )(\d+)',data)
 assert codes and codes[-1]=='0' and 'Error installing zip file' not in data,kind+' updater result not confirmed'
 return data
print('Installing signed ROM without formatting data.',flush=True);romlog=install(stage+'/rom.zip','rom')
assert 'gta3xlwifi' in romlog
assert sh('sha256sum '+marker).split()[0]==markerhash
actual=read('boot');old=(private/'baseline/boot.img').read_bytes();assert actual==boot+old[len(boot):],'Boot readback differs'
for name in ['vendor','dtbo','vbmeta']:assert sh('sha256sum '+block+name).split()[0]==firmware[name]['sha256']
assert hashlib.sha256(read('recovery')).hexdigest()==rec['full_partition_sha256'],'Recovery payload/header unexpectedly changed'
sh('rm '+stage+'/rom.zip')
# Let the original GApps updater mount its target filesystems itself.
for mount in ['/system_root','/product','/mnt/system']:
 if any(x.split()[1]==mount for x in sh('cat /proc/mounts').splitlines()):sh('umount '+mount)
print('Installing unchanged original ARM64 MindTheGapps ZIP.',flush=True);gappslog=install(stage+'/gapps.zip','gapps')
assert 'Done!' in gappslog and 'This package is built for arm64 but your device is arm' not in gappslog
assert sh('sha256sum '+marker).split()[0]==markerhash
for name in ['vendor','dtbo','vbmeta']:assert sh('sha256sum '+block+name).split()[0]==firmware[name]['sha256']
result={'passed':True,'installed_at_utc':datetime.now(timezone.utc).isoformat(),'build_incremental':build,'rom_zip_sha256':signature['rom_zip_sha256'],'gapps_zip_sha256':gappssha,'gapps_zip_unmodified':True,'recovery_bionic_arch':'arm64','rom_updater_exit_code':0,'gapps_updater_exit_code':0,'data_formatted':False,'pre_android_storage_marker_preserved':True,'boot_full_readback_verified':True,'vendor_dtbo_vbmeta_preserved':True,'recovery_preserved':True,'hardware_tested':False}
(a.release/'gapps-install-check.json').write_text(json.dumps(result,indent=2)+'\n');(private/'storage-marker.json').write_text(json.dumps({'marker':marker,'sha256':markerhash},indent=2)+'\n')
sh('rm '+stage+'/gapps.zip; rmdir '+stage)
print('ROM and original GApps installed; updater results and preserved firmware verified.',flush=True)
