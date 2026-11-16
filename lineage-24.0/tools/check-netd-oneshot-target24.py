#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind rebuilt actual netd to the oneshot null-global regression and unchanged networking guards."""
import argparse,hashlib,json,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','archive','geometry','host-proof','reference','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());r=json.loads(a.host_proof.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256']
assert r['passed'] and r['original_null_global_reproduced'] and r['fixed_global_identity_and_failure_propagation_passed'] and not r['policy_kernel_crypto_and_boot_failure_guards_changed']
for name,h in r['source_sha256'].items():assert sha(a.top/name)==h
assert sha(a.top/'system/netd/server/NetdConstants.cpp')==r['unchanged_restore_helpers_sha256']
assert sha(a.top/'system/netd/server/Controllers.cpp')==r['unchanged_controllers_source_sha256']
with zipfile.ZipFile(a.archive) as z,zipfile.ZipFile(a.reference) as old:
 b=z.read('SYSTEM/bin/netd');h=hashlib.sha256(b).hexdigest();assert sha(a.top/'out/target/product/gta3xlwifi/system/bin/netd')==h
 previous=hashlib.sha256(old.read('SYSTEM/bin/netd')).hexdigest();assert h!=previous
 # Failure guard and all real provider/kernel admission remain the same bytes.
 rc=z.read('SYSTEM/etc/init/netd.rc');assert rc==old.read('SYSTEM/etc/init/netd.rc') and b'reboot_on_failure reboot,netd1shot-fail' in rc
report={'passed':True,'scope':__doc__,'archive_sha256':g['archive_sha256'],'actual_netd_sha256':h,'reference_netd_sha256':previous,'netd_init_rc_sha256':hashlib.sha256(rc).hexdigest(),'host_regression_report_sha256':sha(a.host_proof),'real_provider_and_boot_failure_guard_retained':True,'hardware_boot_or_networking_proven':False,'flash_ready':False};a.output.write_text(json.dumps(report,indent=2)+'\n');print('PASS actual rebuilt netd, null-global regression binding and unchanged boot-failure guard')
