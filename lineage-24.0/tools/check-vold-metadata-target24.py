#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the actual replacement vold to the null-predicate regression and unchanged FBE fstab."""
import argparse,hashlib,json,struct,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','archive','geometry','host-proof','reference','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256']
h=json.loads(a.host_proof.read_text());assert h['passed'] and h['baseline_null_dereference_reproduced'] and h['fixed_cases_passed']==7
assert h['source_sha256']['system/vold/FsCrypt.cpp']==sha(a.top/'system/vold/FsCrypt.cpp')
with zipfile.ZipFile(a.archive) as z,zipfile.ZipFile(a.reference) as old:
 b=z.read('SYSTEM/bin/vold');previous=old.read('SYSTEM/bin/vold');assert b!=previous
 assert hashlib.sha256(b).hexdigest()==sha(a.top/'out/target/product/gta3xlwifi/system/bin/vold')
 assert b[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',b,18)[0]==183
 fstab=z.read('ROOT/fstab.exynos7904');assert fstab==old.read('ROOT/fstab.exynos7904') and b'fileencryption=ice' in fstab
r={'passed':True,'scope':__doc__,'archive_sha256':g['archive_sha256'],'new_vold_sha256':hashlib.sha256(b).hexdigest(),'previous_vold_sha256':hashlib.sha256(previous).hexdigest(),'new_vold_matches_build_output':True,'host_regression_report_sha256':sha(a.host_proof),'actual_fstab_sha256':hashlib.sha256(fstab).hexdigest(),'fstab_byte_identical_and_file_encryption_retained':True,'hardware_FBE_proven':False,'flash_ready':False};a.output.write_text(json.dumps(r,indent=2)+'\n');print('PASS actual rebuilt vold and byte-identical FBE fstab')
