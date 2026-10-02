#!/usr/bin/env python3
"""Initialize clean, pinned SM-T510 source checkouts. Never flash a device."""
import argparse, hashlib, shutil, subprocess, urllib.request
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--sync',action='store_true',help='Download upstream Android sources');a=p.parse_args()
R=Path('/srv/android');I=Path(__file__).resolve().parent.parent
REPO=Path.home()/'bin/repo';REPO.parent.mkdir(exist_ok=True)
def run(*args,cwd=None):subprocess.run([str(x) for x in args],cwd=cwd,check=True)
def clone(name,branch,path):
 if path.exists():raise SystemExit(f'Refusing to replace existing checkout: {path}')
 path.parent.mkdir(parents=True,exist_ok=True)
 run('git','clone','--branch',branch,f'https://github.com/oddhap/{name}.git',path)
def sha(path,expected):
 if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise SystemExit(f'Checksum mismatch: {path}')
if not a.sync:raise SystemExit('This initializes new sources; pass --sync to download the pinned checkouts.')
for kind in ['lineage-19.1','twrp-12.1']:
 path=R/'src'/kind
 if path.exists():raise SystemExit(f'Refusing to replace existing checkout: {path}')
if not REPO.exists():urllib.request.urlretrieve('https://storage.googleapis.com/git-repo-downloads/repo',REPO);REPO.chmod(0o755)
for kind in ['lineage-19.1','twrp-12.1']:
 top=R/'src'/kind;top.mkdir(parents=True)
 run(REPO,'init','-u','https://github.com/oddhap/android_build_samsung_gta3xlwifi.git','-b','main','-m',f'manifests/{kind}-source-manifest.xml','--depth=1','--no-clone-bundle',cwd=top)
 run(REPO,'sync','-c','-j8','--no-clone-bundle','--no-tags','--fail-fast',cwd=top)
 device='android_device_samsung_gta3xlwifi'+('_twrp' if kind=='twrp-12.1' else '')
 clone(device,kind,top/'device/samsung/gta3xlwifi')
clone('android_kernel_samsung_gta3xlwifi','lineage-19.1',R/'src/kernel-gta3xlwifi')
clone('android_vendor_samsung_gta3xlwifi','lineage-19.1',R/'vendor-source')
tc=R/'toolchains/aarch64-linux-android-4.9'
if tc.exists():raise SystemExit(f'Refusing to replace toolchain: {tc}')
tc.parent.mkdir(parents=True,exist_ok=True)
run('git','clone','--branch','android-9.0.0_r61','https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9',tc)
run('git','-C',tc,'checkout','961622e926a1b21382dba4dd9fe0e5fb3ee5ab7c')
images=R/'vendor-stock/images';images.mkdir(parents=True,exist_ok=True)
run('gh','release','download','stock-cwa1','--repo','oddhap/android_vendor_samsung_gta3xlwifi','--dir',images)
sha(images/'vendor.img','4cc684231b4a1c355169cea61b4ea5196401bc5f68c7f74a32c1ec290abc0006')
extracted=R/'vendor-stock/extracted/vendor';extracted.parent.mkdir(parents=True,exist_ok=True)
if extracted.exists():raise SystemExit(f'Refusing to replace vendor extraction: {extracted}')
shutil.copytree(R/'vendor-source/proprietary',extracted,symlinks=True)
pre=R/'src/twrp-12.1/device/samsung/gta3xlwifi/prebuilt';pre.mkdir(parents=True)
run('gh','release','download','tested-recovery-inputs','--repo','oddhap/android_device_samsung_gta3xlwifi_twrp','--dir',pre)
sha(pre/'Image','445f0b44dd53f2bc464e95e2729307cc2cea1baf6f35db9b22327b0f7c352edd')
sha(pre/'dtbo.img','b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b')
(R/'tools').mkdir(exist_ok=True);(R/'patches').mkdir(exist_ok=True)
for src in (I/'tools').iterdir():
 if src.is_file():shutil.copy2(src,R/'tools'/src.name)
shutil.copytree(I/'patches',R/'patches',dirs_exist_ok=True)
for name in ['build-native-rom.sh','build-kernel-smoke.sh','build-twrp.sh','fix-twrp-relink-dependencies.py','fix-twrp-fbe-startup.py','verify-twrp-image.py']:
 shutil.copy2(I/'tools'/name,R/name)
print('Pinned sources and inputs staged. Apply platform patches and build; see README.md.')
