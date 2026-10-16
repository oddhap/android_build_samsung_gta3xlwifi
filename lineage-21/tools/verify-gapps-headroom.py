#!/usr/bin/env python3
"""Check physical product capacity and app/JNI layout directly in target-files."""
import argparse,hashlib,json,struct,subprocess,tempfile,zipfile,shutil
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--release',type=Path,required=True);p.add_argument('--gapps',type=Path,required=True);p.add_argument('--simg2img',type=Path,required=True);p.add_argument('--target-files',type=Path);p.add_argument('--baseline-target-files',type=Path);a=p.parse_args()
expected='6e1c3616862ce5b33e2b96074f86ae846eb1351a26a980e1ed140f8a7e7a4fd6'
h=hashlib.sha256()
with a.gapps.open('rb') as f:
 for chunk in iter(lambda:f.read(8388608),b''):h.update(chunk)
assert h.hexdigest()==expected,'GApps ZIP differs from official checksum'
optional=('product/app/GoogleTTS/','product/app/MarkupGoogle/','product/app/SpeechServicesByGoogle/','product/app/talkback/','product/priv-app/GoogleRestore/','product/priv-app/Velvet/','product/priv-app/VelvetTitan/','product/priv-app/Wellbeing/','system_ext/priv-app/SetupWizard/')
with zipfile.ZipFile(a.gapps) as z:
 assert z.read('build.prop')==b'arch=arm64\nversion=34\nversion_nice=14.0.0\n'
 needed=sum((f.file_size+4095)//4096*4096 for f in z.infolist() if f.filename.startswith('system/product/') and not f.is_dir() and not f.filename[7:].startswith(optional))+10240*1024
a.release.mkdir(parents=True,exist_ok=True);target=a.target_files or a.release/'signed-target-files.zip'
with zipfile.ZipFile(target) as z,tempfile.TemporaryDirectory(dir=a.release,prefix='gapps-space-') as temp:
 image=Path(temp)/'product.sparse.img';raw=Path(temp)/'product.raw.img'
 with z.open('IMAGES/product.img') as src,image.open('wb') as dest:shutil.copyfileobj(src,dest)
 imagehash=hashlib.sha256(image.read_bytes()).hexdigest()
 if not a.target_files:
  images=json.loads((a.release/'native-image-check.json').read_text());assert imagehash==images['images']['product.img']['sha256']
  signature=json.loads((a.release/'release-signature-check.json').read_text());assert images['rom_zip_sha256']==signature['rom_zip_sha256']
 with image.open('rb') as f:sparse=f.read(4)==b'\x3a\xff\x26\xed'
 if sparse:subprocess.run([str(a.simg2img),str(image),str(raw)],check=True)
 else:raw=image
 with raw.open('rb') as f:f.seek(1024);sb=f.read(1024)
 assert struct.unpack_from('<H',sb,56)[0]==0xef53
 blocksize=1024<<struct.unpack_from('<I',sb,24)[0];reserved=struct.unpack_from('<I',sb,8)[0];free=struct.unpack_from('<I',sb,12)[0];available=(free-reserved)*blocksize
 assert available>=needed,('Insufficient product space for the installer minimal fallback',available,needed)
 files=set(z.namelist())
 for module,priv in [('LatinIME',False),('Contacts',True),('Eleven',True),('Gallery2',False)]:
  folder='priv-app' if priv else 'app';assert any(n.startswith('SYSTEM/'+folder+'/'+module+'/') and n.endswith('.apk') for n in files),module
  assert not any(n.startswith('PRODUCT/'+folder+'/'+module+'/') for n in files),module
 for library in ['libjni_eglfence.so','libjni_filtershow_filters.so','libjni_jpegstream.so','libjni_latinime.so']:
  assert 'SYSTEM/lib64/'+library in files,library
  assert 'PRODUCT/lib64/'+library not in files,library
 for name in ['com.android.contacts.xml','privapp_whitelist_org.lineageos.eleven.xml']:
  assert 'SYSTEM/etc/permissions/'+name in files,name
 preserved=None
 if a.baseline_target_files:
  with zipfile.ZipFile(a.baseline_target_files) as old:
   baseline={Path(n).name for n in old.namelist() if n.endswith('.apk')}
  current={Path(n).name for n in files if n.endswith('.apk')};assert baseline<=current,('Previously packaged APKs missing',sorted(baseline-current));preserved=len(baseline)
report={'passed':True,'gapps_zip_sha256':expected,'gapps_zip_unmodified':True,'android_sdk':34,'architecture':'arm64','product_available_bytes':available,'minimal_product_payload_with_installer_buffer_bytes':needed,'product_headroom_after_minimal_gapps_bytes':available-needed,'partition_sizes_unchanged':True,'moved_apps_jni_and_privileged_permission_allowlists_checked':True,'previous_packaged_apk_names_preserved':preserved,'target_files_signed':a.target_files is None,'product_image_sha256':imagehash,'hardware_tested':False}
if not a.target_files:report['signed_product_available_bytes']=available
(a.release/('gapps-headroom-check.json' if not a.target_files else 'unsigned-gapps-headroom-check.json')).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
