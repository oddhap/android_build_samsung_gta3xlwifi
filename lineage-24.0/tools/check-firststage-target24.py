#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify actual SAR root init reaches a static current-platform first stage.

Checks actual target-files links/ELF segments/build output identity and all early
mountpoint directories. Does not execute init or establish a successful device boot.
"""
import argparse,hashlib,json,stat,struct,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','archive','geometry','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256']
name='gta3xlwifi_first_stage_init'
with zipfile.ZipFile(a.archive) as z:
 i=z.getinfo('ROOT/init');assert stat.S_ISLNK(i.external_attr>>16) and z.read('ROOT/init')==('/system/bin/'+name).encode()
 b=z.read('SYSTEM/bin/'+name);assert b[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',b,18)[0]==183
 off=struct.unpack_from('<Q',b,32)[0];size,count=struct.unpack_from('<HH',b,54);assert size>=56 and count>0 and off+size*count<=len(b)
 assert all(struct.unpack_from('<I',b,off+i*size)[0]!=3 for i in range(count)),'Stage one must not require the dynamic linker before filesystem setup'
 assert b'init first stage started!' in b and b'/system/bin/init' in b and b'selinux_setup' in b
 assert hashlib.sha256(b).hexdigest()==sha(a.top/'out/target/product/gta3xlwifi/system/bin'/name)
 for d in ['dev','proc','sys','mnt','debug_ramdisk','second_stage_resources']:assert z.getinfo('ROOT/'+d+'/').is_dir()
 fstab=z.read('ROOT/fstab.exynos7904').decode();assert '/vendor ext4 ro wait,first_stage_mount' in fstab and '/product ext4 ro wait,first_stage_mount' in fstab
 assert 'fileencryption=ice' in fstab and 'use_dynamic_partitions=true' not in z.read('META/misc_info.txt').decode()
 second=z.read('SYSTEM/bin/init');assert b'Second-stage init requires an argument' in second
r={'passed':True,'scope':__doc__,'archive_sha256':g['archive_sha256'],'root_init_target':'/system/bin/'+name,'static_arm64_first_stage_sha256':hashlib.sha256(b).hexdigest(),'first_stage_matches_build_output':True,'current_platform_selinux_setup_handoff_present':True,'early_mountpoints_present':True,'vendor_product_first_stage_mount_and_FBE_preserved':True,'device_boot_proven':False,'flash_ready':False}
a.output.write_text(json.dumps(r,indent=2)+'\n');print('PASS actual static first stage and SAR root composition')
