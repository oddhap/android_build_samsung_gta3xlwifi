#!/usr/bin/env python3
"""Check the actual signed vendor filesystem contains the reviewed USB owner."""
import argparse,hashlib,json,subprocess,tempfile,zipfile,shutil
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('target_files',type=Path)
p.add_argument('--top',type=Path,default=Path('/srv/android/src/lineage-21.0-arm64'))
p.add_argument('--report',type=Path,required=True)
a=p.parse_args()
port=Path(__file__).resolve().parents[1]
locked=json.loads((port/'notes/source-inputs.lock.json').read_text())['inputs']['vendor_sha256']
expected=(port/'configs/init.exynos7904.usb.rc').read_bytes()
with zipfile.ZipFile(a.target_files) as z,tempfile.TemporaryDirectory(prefix='mtp-package-') as directory:
 d=Path(directory);sparse=d/'vendor.img';raw=d/'vendor.raw.img'
 with z.open('IMAGES/vendor.img') as src,sparse.open('wb') as dst:shutil.copyfileobj(src,dst)
 h=hashlib.sha256(sparse.read_bytes()).hexdigest()
 if h!=locked:raise SystemExit('Signed vendor differs from the locked reviewed image')
 host=a.top/'out/host/linux-x86/bin'
 subprocess.run([str(host/'simg2img'),str(sparse),str(raw)],check=True)
 if raw.stat().st_size!=343932928:raise SystemExit('Wrong physical vendor size')
 usb=subprocess.run([str(host/'debugfs_static'),'-R','cat /etc/init/init.exynos7904.usb.rc',str(raw)],check=True,capture_output=True).stdout
 if usb!=expected:raise SystemExit('Packaged USB script differs from reviewed MTP fix')
 rc=d/'init.exynos7904.usb.rc';rc.write_bytes(usb)
 subprocess.run([str(host/'host_init_verifier'),str(rc)],check=True)
report={'passed':True,'signed_target_files_vendor_sha256':h,'usb_rc_sha256':hashlib.sha256(usb).hexdigest(),'usb_source_matches_packaged_filesystem':True,'init_verifier_passed':True,'hardware_tested':False}
a.report.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
