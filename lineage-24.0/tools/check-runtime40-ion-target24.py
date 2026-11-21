#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the actual packaged ION labels and strict permissions to physical graphics failures.

Runtime40 variant (only change): /product is folded into /system (snapshot40);
no product image, product members live under SYSTEM/product/. Recorded product output
paths are mapped to system/product with identical content."""
import argparse,hashlib,json,zipfile
from pathlib import Path
def moved(path):
 # Snapshot40 folds product into system. Map a recorded product output path to its
 # system/product location and require the stale product location to be gone.
 s=str(path);old='/out/target/product/gta3xlwifi/product/';new='/out/target/product/gta3xlwifi/system/product/'
 if old not in s:return Path(s)
 assert not Path(s).exists(),('Stale separate product output still present',s)
 return Path(s.replace(old,new))
p=argparse.ArgumentParser()
for n in ['top','archive','geometry','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();A=Path('/srv/android/artifacts/lineage-24.0-arm64')
def sha(f):
 h=hashlib.sha256()
 with f.open('rb') as s:
  for b in iter(lambda:s.read(1048576),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256'];labels=A/'ion2-built-labels-20261120-01/report.json';access=A/'ion2-built-access-20261120-01/report.json';l=json.loads(labels.read_text());r=json.loads(access.read_text());assert l['passed'] and l['HAL_server_memberships_exact'] and r['passed'] and r['no_permissive_domains'];strict=A/'ion2-policy-strict-20261120-01/strict/report.json';assert l['strict_report_sha256']==sha(strict);assert r['policy_sha256']==sha(strict.parent/'strict.policy')
for name,h in l['inputs_sha256'].items():assert sha(moved(name))==h
for name,h in r['inputs_sha256'].items():assert sha(moved(name))==h
files={}
with zipfile.ZipFile(a.archive) as z:
 for member in ['SYSTEM/etc/selinux/plat_file_contexts','SYSTEM/system_ext/etc/selinux/system_ext_file_contexts','SYSTEM/product/etc/selinux/product_file_contexts']:
  h=hashlib.sha256(z.read(member)).hexdigest();assert h in l['inputs_sha256'].values();files[member]=h
 assert '/dev/ion -c u:object_r:ion_device:s0' in z.read('SYSTEM/system_ext/etc/selinux/system_ext_file_contexts').decode()
v=A/'btaudio-vendor-20261120-01/report.json';assert sha(v)==g['vendor_composition_report_sha256'];tree=json.loads((v.parent/'after/report.json').read_text())['entries'];vendor_fc=tree['/etc/selinux/vendor_file_contexts']['sha256'];assert vendor_fc in l['inputs_sha256'].values();files['VENDOR_IMAGE/etc/selinux/vendor_file_contexts']=vendor_fc
a.output.write_text(json.dumps(dict(passed=True,scope=__doc__,archive_sha256=g['archive_sha256'],context_members=files,strict_report_sha256=sha(strict),label_proof_sha256=sha(labels),permission_proof_sha256=sha(access),generic_device_access_denied=True,hardware_graphics_proven=False,flash_ready=False),indent=2)+'\n');print('PASS packaged exact ION context and strict scoped graphics-client permission proofs')
