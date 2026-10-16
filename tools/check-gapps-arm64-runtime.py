#!/usr/bin/env python3
"""Collect GApps runtime evidence without account contents or UI screenshots."""
import argparse,json,subprocess,struct,time,re,os
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--release',type=Path,required=True);a=p.parse_args()
r=Path(__file__).resolve().parent.parent;adb='/opt/homebrew/bin/adb';os.umask(0o077)
stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');private=r/'.private/gapps'/('runtime-'+stamp);private.mkdir(parents=True,mode=0o700)
def run(*args,binary=False):
 b=subprocess.check_output([adb,*args],timeout=30);return b if binary else b.decode().strip()
def shell(s):return run('shell',s)
signature=json.loads((a.release/'release-signature-check.json').read_text());assert signature['passed']
assert shell('getprop ro.build.version.incremental')==signature['build_incremental']
assert shell('getprop sys.boot_completed')=='1' and shell('getprop sys.user.0.ce_available')=='true'
assert shell('getprop ro.product.cpu.abilist64')=='arm64-v8a' and shell('getprop ro.zygote')=='zygote64_32'
assert shell('getenforce')=='Enforcing' and shell('getprop ro.crypto.state')=='encrypted'
assert shell('id -u')=='0','adb root is required for process ABI evidence'
storage=json.loads((r/'.private/gapps/storage-marker.json').read_text())
assert storage['marker']=='/data/gapps-storage-check'
assert shell('sha256sum '+storage['marker']).split()[0]==storage['sha256'],'Pre-Android storage marker changed'
packages={}
for name in ['com.google.android.gms','com.google.android.gsf','com.android.vending']:
 paths=shell('pm path '+name);assert paths.startswith('package:'),name
 info=shell('dumpsys package '+name);(private/(name+'.txt')).write_text(info)
 assert 'SYSTEM' in info and 'PRIVILEGED' in info,name
 version=re.search(r'\bversionName=(\S+)',info);abi=re.search(r'\bprimaryCpuAbi=(\S+)',info)
 packages[name]={'installed':True,'version':version.group(1) if version else None,'primary_cpu_abi':abi.group(1) if abi else None,'system_privileged':True}
component=shell('cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER com.android.vending').splitlines()[-1]
assert component.startswith('com.android.vending/')
launch=shell('am start -W -n '+component);assert 'Status: ok' in launch,launch
# Allow normal Play initialization before measuring process stability.
time.sleep(15)
pids={}
for name in ['com.android.vending','com.google.android.gms']:
 pid=shell('pidof '+name);assert pid.isdigit(),name
 elf=run('exec-out','head -c 20 /proc/'+pid+'/exe',binary=True)
 assert elf[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',elf,18)[0]==183,name
 pids[name]=pid
start=time.monotonic()
for sample in range(12):
 time.sleep(5)
 assert all(shell('pidof '+name)==pid for name,pid in pids.items()),'A monitored Google process restarted'
crashes=run('logcat','-b','crash','-d');(private/'crash-buffer.txt').write_text(crashes)
assert not re.search(r'Process: (com\.google\.android\.(?:gms|gsf)|com\.android\.vending)\b',crashes),'Google app crash in current boot; inspect private log'
assert 'com.android.vending/' in shell('dumpsys activity activities'),'Play Store has no activity'
report={'passed':True,'checked_at_utc':datetime.now(timezone.utc).isoformat(),'build_incremental':signature['build_incremental'],'rom_zip_sha256':signature['rom_zip_sha256'],'packages':packages,'play_store_launch_passed':True,'gms_and_play_store_native_aarch64':True,'monitored_processes_stable_seconds':round(time.monotonic()-start,1),'google_process_crashes_in_current_boot':False,'selinux':'Enforcing','encryption':'encrypted/file','pre_android_storage_marker_survived_boot':True,'account_contents_collected':False,'app_download_physically_confirmed':False}
(a.release/'gapps-runtime-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
