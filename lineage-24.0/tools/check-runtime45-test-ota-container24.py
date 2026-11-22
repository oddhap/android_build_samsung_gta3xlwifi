#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify actual OTA signature/CRC, payload identities and pre-write Edify guards.

Runtime45 variant: the TWRP vendor quiesce script runs after the first recovery
preflight and before the (unchanged) vendor-unmounted guard; its result is not
trusted. Runtime44 variant: the LineageOS addon.d backup/restore emitted by
releasetools.py is required in its reviewed position: backup after both
guards with vendor/product write-protected, release + vendor guard again before
the first write, restore only after the last write; the packaged guard and
backuptool scripts must equal the reviewed sources.

Permits an unused diagnostic recovery.img only if it exactly matches target-files
and has no script reference. No partition or device operation is performed.
"""
import argparse,ast,hashlib,json,re,shutil,struct,subprocess,zipfile
from pathlib import Path,PurePosixPath
p=argparse.ArgumentParser(description=__doc__)
for n in ['ota','target-files','geometry','certificate','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and sha(a.target_files)==g['archive_sha256']
with zipfile.ZipFile(a.ota) as z,zipfile.ZipFile(a.target_files) as t:
 names=z.namelist();assert len(names)==len(set(names))
 for name in names:
  path=PurePosixPath(name);assert not path.is_absolute() and '..' not in path.parts
  assert not name.endswith(('.pk8','.p12','.pfx','.key')) and not name.endswith('.pem'),name
 assert z.testzip() is None
 metadata=dict(line.split('=',1) for line in z.read('META-INF/com/android/metadata').decode().splitlines() if '=' in line)
 assert metadata['ota-type']=='BLOCK' and metadata['pre-device']=='gta3xlwifi' and metadata['post-sdk-level']=='37'
 assert metadata['post-security-patch-level']==g['security_patch']
 assert metadata.get('ota-wipe')!='yes' and metadata.get('ota-downgrade')!='yes' and 'payload.bin' not in names
 script=z.read('META-INF/com/google/android/updater-script').decode();(O/'updater-script.edify').write_text(script)
 assert '--apply' not in script and all(x not in script for x in ['write_raw_image(', 'format(', 'delete_recursive(', 'reboot_now(', 'set_stage(', 'update_dynamic_partitions(', '/userdata', '/mmcblk0p16'])
 assert '"recovery.img"' not in script and 'install-recovery.sh' not in script
 block=re.findall(r'block_image_update\("([^"]+)"',script)
 prefix='/dev/block/platform/13500000.dwmmc0/by-name/'
 assert block==[prefix+n for n in ['system','vendor']] and 'by-name/product' not in script  # runtime40: product folded into system
 raw=re.findall(r'package_extract_file\("([^"]+)", "(/dev/[^"]+)"',script);assert raw==[('boot.img',prefix+'boot')]
 guard='run_program("/tmp/gta3xlwifi_recovery_header_sync", "--preflight", '
 assert script.count(guard)==2
 first_guard=script.index(guard);mount_guard=script.index('run_program("/sbin/sh", "/tmp/vendor-unmounted-check.sh")')
 first_write=min(script.index('block_image_update('),script.index('package_extract_file("boot.img", "/dev/'))
 assert first_guard<mount_guard<first_write and script.rindex(guard)>first_write
 target_word=g['images']['boot.img']['os_version_word'];assert script.count('"0x%08x"'%target_word)==2
 commands=re.findall(r'run_program\("([^"]+)"',script);H,S,B='/tmp/gta3xlwifi_recovery_header_sync','/sbin/sh','/tmp/install/bin/backuptool.sh'
 assert commands==[H,S,S,S,S,B,S,S,S,B,S,H],commands
 quiesce=script.index('run_program("/sbin/sh", "/tmp/recovery-vendor-quiesce.sh");');assert first_guard<quiesce<mount_guard and script.count('recovery-vendor-quiesce.sh");')==2
 plink=script.index('assert(run_program("/sbin/sh", "/tmp/recovery-product-link.sh") == "0" ||');assert quiesce<plink<mount_guard<script.index('backuptool.sh", "backup"')
 last_write=max(script.rindex('block_image_update('),script.rindex('package_extract_file("boot.img", "/dev/'))
 backup=script.index('backuptool.sh", "backup", "'+prefix+'system", "ext4")');restore=script.index('backuptool.sh", "restore", "'+prefix+'system", "ext4")')
 protect=script.index('addon-vendor-guard.sh", "protect") == "0" ||');release=script.index('addon-vendor-guard.sh", "release") == "0" ||')
 assert mount_guard<protect<backup<release<script.rindex('run_program("/sbin/sh", "/tmp/vendor-unmounted-check.sh")')<first_write
 assert last_write<script.index('if run_program("/sbin/sh", "/tmp/addon-vendor-guard.sh", "protect") == "0" then')<restore<script.rindex(guard)
 assert script.count('package_extract_dir("install", "/tmp/install")')>=1 and script.index('package_extract_dir("install", "/tmp/install")')<backup
 def elf(data,bits,machine):
  assert data[:6]==b'\x7fELF'+bytes([bits//32,1]) and struct.unpack_from('<H',data,18)[0]==machine
  if bits==64:offset=struct.unpack_from('<Q',data,32)[0];size,num=struct.unpack_from('<HH',data,54)
  else:offset=struct.unpack_from('<I',data,28)[0];size,num=struct.unpack_from('<HH',data,42)
  assert size and num and offset+size*num<=len(data)
  assert all(struct.unpack_from('<I',data,offset+i*size)[0]!=3 for i in range(num)),'Dynamic interpreter in recovery executable'
 helper=z.read('recovery-header-sync');assert helper==t.read('SYSTEM/bin/gta3xlwifi_recovery_header_sync');elf(helper,32,40)
 assert b'--apply' not in helper and b'--preflight' in helper
 updater=z.read('META-INF/com/google/android/update-binary');assert updater==t.read('OTA/bin/updater')
 bits=32 if updater[4]==1 else 64;elf(updater,bits,40 if bits==32 else 183)
 source=ast.parse(t.read('META/releasetools.py'))
 assignment=next(n for n in source.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='_VENDOR_MOUNT_GUARD' for x in n.targets))
 assert z.read('vendor-unmounted-check.sh')==ast.literal_eval(assignment.value)
 q=next(n for n in source.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='_VENDOR_QUIESCE' for x in n.targets))
 assert z.read('recovery-vendor-quiesce.sh')==ast.literal_eval(q.value)
 pl=next(n for n in source.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='_PRODUCT_LINK' for x in n.targets))
 assert z.read('recovery-product-link.sh')==ast.literal_eval(pl.value)
 addon=next(n for n in source.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='_ADDON_GUARD' for x in n.targets))
 assert z.read('addon-vendor-guard.sh')==ast.literal_eval(addon.value)
 for n in ['backuptool.sh','backuptool.functions']:assert z.read('install/bin/'+n)==t.read('INSTALL/bin/'+n),n
 assert z.read('boot.img')==t.read('IMAGES/boot.img')
 if 'recovery.img' in names:assert z.read('recovery.img')==t.read('IMAGES/recovery.img')
 assert z.read('META-INF/com/android/otacert')==a.certificate.read_bytes()
# Match the signed range and footer definitions in the actual recovery verifier.
length=a.ota.stat().st_size
with a.ota.open('rb') as f:
 f.seek(-6,2);footer=f.read();signature_start,marker,comment=struct.unpack('<HHH',footer)
 assert marker==0xffff and 6<signature_start<=comment<=65535
 eocd_start=length-comment-22;assert eocd_start>0
 f.seek(eocd_start);eocd=f.read();assert eocd[:4]==b'PK\x05\x06' and b'PK\x05\x06' not in eocd[4:]
 assert struct.unpack_from('<H',eocd,20)[0]==comment
 f.seek(length-signature_start);der=f.read(signature_start-6);(O/'signature.der').write_bytes(der)
 signed_length=length-comment-2;f.seek(0)
 signed=O/'signed-range.bin'
 with signed.open('wb') as dst:
  remaining=signed_length
  while remaining:
   b=f.read(min(1024*1024,remaining));assert b;dst.write(b);remaining-=len(b)
command=['openssl','cms','-verify','-binary','-inform','DER','-in',str(O/'signature.der'),'-content',str(signed),'-certfile',str(a.certificate),'-nointern','-noverify','-out','/dev/null']
r=subprocess.run(command,capture_output=True,text=True);(O/'signature.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
signed.unlink()
report={'passed':True,'scope':__doc__,'ota_sha256':sha(a.ota),'ota_bytes':length,'target_files_sha256':g['archive_sha256'],'whole_zip_crc_checked':True,'signature_verified_with_explicit_public_certificate':True,'certificate_sha256':sha(a.certificate),'signature_command':command,'metadata':metadata,'partition_writes':block+[x[1] for x in raw],'read_only_recovery_preflight_count':2,'twrp_vendor_quiesce_before_vendor_guard':True,'product_link_before_backup':True,'addon_d_backup_restore':'backup between guards with vendor/product read-only, restore after last write','guards_precede_all_partition_writes':True,'recovery_img_present_but_unreferenced':'recovery.img' in names,'static_updater_bits':bits,'static_updater_sha256':hashlib.sha256(updater).hexdigest(),'static_arm32_probe_sha256':hashlib.sha256(helper).hexdigest(),'transfer_data_validated_by_this_tool':False,'device_touched':False,'Android17_FBE_validated':False,'flash_ready':False}
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS actual OTA container, signature, CRC, identities and pre-write guards')
