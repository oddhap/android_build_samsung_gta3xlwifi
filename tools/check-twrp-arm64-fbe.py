#!/usr/bin/env python3
"""Check native ARM64 recovery CE access; credentials are entered only on screen."""
import argparse,hashlib,json,subprocess,time,re,struct,os
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('phase',choices=['before','recovery','after']);p.add_argument('--credential',choices=['none','pin'],required=True);p.add_argument('--recovery',type=Path,required=True);p.add_argument('--rom',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args()
assert re.fullmatch('[a-z0-9-]+',a.label)
r=Path(__file__).resolve().parent.parent;adb='/opt/homebrew/bin/adb';private=r/'.private/gapps'/('fbe-'+a.label);private.mkdir(parents=True,exist_ok=True,mode=0o700);os.umask(0o077)
marker='/data/media/0/Download/.gapps-arm64-recovery-check';baseline=private/'baseline.json';check=json.loads((a.recovery/'image-check.json').read_text());rom=json.loads((a.rom/'release-signature-check.json').read_text())
def run(*args,binary=False):
 b=subprocess.check_output([adb,*args],timeout=30);return b if binary else b.decode().strip()
def sh(c):return run('shell',c)
def crypto_hashes():
 text=sh('find /data/misc/vold/user_keys /data/unencrypted -type f -exec sha256sum {} \\;');return {line.split(maxsplit=1)[1]:line.split()[0] for line in text.splitlines()}
def marker_bytes():return run('exec-out','cat '+marker,binary=True)
def android():
 assert sh('getprop ro.twrp.version')=='' and sh('getprop sys.boot_completed')=='1'
 assert sh('getprop ro.build.version.incremental')==rom['build_incremental']
 assert sh('getprop sys.user.0.ce_available')=='true' and sh('getenforce')=='Enforcing'
 assert sh('getprop ro.crypto.state')=='encrypted' and sh('getprop ro.crypto.type')=='file'
 lock=sh('dumpsys lock_settings');(private/('lock-'+a.phase+'.txt')).write_text(lock)
 assert ('CredentialType: NONE' if a.credential=='none' else 'CredentialType: PIN') in lock
assert sh('id -u')=='0'
installed=json.loads((a.recovery/'install-check.json').read_text())
assert sh('sha256sum /dev/block/platform/13500000.dwmmc0/by-name/recovery').split()[0]==installed['full_partition_sha256']
if a.phase=='before':
 android();assert not baseline.exists(),'Use a new label rather than overwrite FBE evidence'
 assert sh('test -d /data/media/0/Download && echo present')=='present'
 sh('dd if=/dev/urandom of='+marker+' bs=64 count=1 2>/dev/null; chmod 600 '+marker+'; sync')
 keys=crypto_hashes();assert len(keys)>=10 and any('/user_keys/ce/0/' in k for k in keys)
 baseline.write_text(json.dumps({'marker_sha256':hashlib.sha256(marker_bytes()).hexdigest(),'crypto_hashes':keys,'credential':a.credential,'build_incremental':rom['build_incremental']},indent=2)+'\n');print('Android FBE marker and private key hashes captured; ready for recovery.')
elif a.phase=='recovery':
 before=json.loads(baseline.read_text());assert sh('getprop ro.twrp.version')=='3.7.1_12' and sh('getprop ro.bionic.arch')=='arm64'
 assert sh('getprop twrp.decrypt.done')=='true','User storage has not decrypted'
 assert sh('getenforce')=='Enforcing'
 assert hashlib.sha256(marker_bytes()).hexdigest()==before['marker_sha256']
 assert run('exec-out','head -c 16 /data/system_ce/0/accounts_ce.db',binary=True)==b'SQLite format 3\0'
 assert crypto_hashes()==before['crypto_hashes'],'Recovery changed persistent encryption-key files'
 for path,field in [('/system/bin/recovery','recovery_elf_sha256'),('/system/lib64/libfscrypttwrp.so','fscrypt_library_sha256')]:
  assert sh('sha256sum '+path).split()[0]==check[field]
 # TWRP can fork a child named recovery (for example its MTP worker).
 # Track the init-owned GUI process rather than require a single pidof result.
 pids=sh('pidof recovery').split();assert pids and all(pid.isdigit() for pid in pids)
 main_pids=[pid for pid in pids if re.search(r'^PPid:\s+1$',sh('cat /proc/'+pid+'/status'),re.M)]
 assert len(main_pids)==1,'Expected one init-owned recovery GUI'
 pid=main_pids[0]
 services=['keystore2','recovery-mobicore','recovery-keymaster','recovery-gatekeeper']
 for name in services:assert sh('getprop init.svc.'+name)=='running',name
 start=time.monotonic()
 for sample in range(12):
  time.sleep(5);assert pid in sh('pidof recovery').split() and sh('getprop twrp.decrypt.done')=='true'
  assert re.search(r'^PPid:\s+1$',sh('cat /proc/'+pid+'/status'),re.M)
  assert hashlib.sha256(marker_bytes()).hexdigest()==before['marker_sha256']
 log=run('exec-out','cat /tmp/recovery.log',binary=True).decode(errors='replace');(private/'recovery.log').write_text(log)
 crashes=run('logcat','-b','all','-d');(private/'logcat.txt').write_text(crashes)
 assert log.count('Starting TWRP ')==1 and not re.search(r'Fatal signal|SIGSEGV',crashes)
 if a.credential=='none':assert 'Successfully decrypted with default password.' in log
 assert crypto_hashes()==before['crypto_hashes']
 sh('printf "\\nrecovery-write-confirmed-'+a.label+'\\n" >> '+marker+'; sync')
 afterhash=hashlib.sha256(marker_bytes()).hexdigest();(private/'recovery-marker-sha256').write_text(afterhash)
 report={'passed':True,'checked_at_utc':datetime.now(timezone.utc).isoformat(),'recovery_image_sha256':check['sha256'],'rom_build':rom['build_incremental'],'userspace_bits':64,'credential':a.credential,'automatic_ce_decryption':a.credential=='none','manual_pin_entry':a.credential=='pin','media_read_write_passed':True,'ce_sqlite_header_readable':True,'encryption_key_file_hashes_unchanged':len(before['crypto_hashes']),'stable_seconds':round(time.monotonic()-start,1),'single_recovery_start':True,'no_fatal_signals':True,'global_selinux':'Enforcing','android_return_tested':False}
 (a.recovery/(a.label+'-recovery-check.json')).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
else:
 android();before=json.loads(baseline.read_text());assert hashlib.sha256(marker_bytes()).hexdigest()==(private/'recovery-marker-sha256').read_text()
 after=crypto_hashes();assert before['crypto_hashes'].keys()==after.keys()
 changed=[k for k,v in before['crypto_hashes'].items() if after[k]!=v];assert set(changed)<= {'/data/unencrypted/per_boot_ref'},changed
 p=a.recovery/(a.label+'-recovery-check.json');report=json.loads(p.read_text());report.update(android_return_tested=True,ce_write_persisted_in_android=True,persistent_encryption_keys_preserved_on_return=True);p.write_text(json.dumps(report,indent=2)+'\n')
 sh('rm '+marker);print('Android return passed; CE write persisted, persistent encryption keys preserved, test marker removed.')
