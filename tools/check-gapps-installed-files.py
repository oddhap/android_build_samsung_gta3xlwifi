#!/usr/bin/env python3
"""Verify the original installer's mandatory payload against mounted filesystems."""
import argparse,hashlib,json,subprocess,zipfile,stat
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--gapps',type=Path,required=True);p.add_argument('--release',type=Path,required=True);p.add_argument('--installation-check',default='gapps-install-check.json');a=p.parse_args()
adb='/opt/homebrew/bin/adb';root=Path(__file__).resolve().parent.parent;block='/dev/block/platform/13500000.dwmmc0/by-name/'
def sh(s):return subprocess.check_output([adb,'shell',s],text=True).strip()
assert sh('getprop ro.bionic.arch')=='arm64' and sh('getprop ro.twrp.version')=='3.7.1_12'
assert Path(a.installation_check).name==a.installation_check
assert json.loads((a.release/a.installation_check).read_text())['passed']
assert hashlib.sha256(a.gapps.read_bytes()).hexdigest()=='6e1c3616862ce5b33e2b96074f86ae846eb1351a26a980e1ed140f8a7e7a4fd6'
mounts=[]
try:
 for name,dest in [('system','/system_root'),('product','/product')]:
  assert not any(line.split()[1]==dest for line in sh('cat /proc/mounts').splitlines()),dest
  sh('mount -t ext4 -o ro,noload '+block+name+' '+dest);mounts.append(dest)
 optional=('system/product/app/GoogleTTS/','system/product/app/MarkupGoogle/','system/product/app/SpeechServicesByGoogle/','system/product/app/talkback/','system/product/priv-app/GoogleRestore/','system/product/priv-app/Velvet/','system/product/priv-app/VelvetTitan/','system/product/priv-app/Wellbeing/','system/system_ext/priv-app/SetupWizard/','system/addon.d/')
 lines=[]
 with zipfile.ZipFile(a.gapps) as z:
  for f in z.infolist():
   if not f.filename.startswith('system/') or f.is_dir() or f.filename.startswith(optional):continue
   if stat.S_ISLNK(f.external_attr>>16):continue
   target='/product/'+f.filename[len('system/product/'):] if f.filename.startswith('system/product/') else '/system_root/system/'+f.filename[len('system/'):]
   assert all(c not in target for c in ['\n','\r',' '])
   lines.append(hashlib.sha256(z.read(f)).hexdigest()+'  '+target)
 manifest=root/'.private/gapps/installed-files.sha256';manifest.write_text('\n'.join(lines)+'\n')
 subprocess.run([adb,'push',str(manifest),'/tmp/gapps-files.sha256'],check=True,capture_output=True)
 output=sh('sha256sum -c /tmp/gapps-files.sha256');assert len(output.splitlines())==len(lines) and all(x.endswith(': OK') for x in output.splitlines())
 assert sh('test -s /system_root/system/addon.d/30-gapps.sh && echo present')=='present'
 space=sh('df -k /product /system_root');(root/'.private/gapps/installed-space.txt').write_text(space+'\n')
 report={'passed':True,'original_mandatory_payload_files_hash_verified':len(lines),'original_gapps_zip_unmodified':True,'addon_d_preservation_script_present':True,'filesystems_verified_read_only':True}
 (a.release/'gapps-installed-files-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
finally:
 sh('rm -f /tmp/gapps-files.sha256')
 for dest in reversed(mounts):sh('umount '+dest)
