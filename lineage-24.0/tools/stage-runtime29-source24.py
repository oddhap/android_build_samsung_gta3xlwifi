#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply reviewed runtime29 policy and updater changes in separate audited steps."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path('/srv/android')
src = root/'src/lineage-24.0-arm64'
art = root/'artifacts/lineage-24.0-arm64'
port = root/'ports/lineage-24.0-arm64/lineage-24.0'
base = port/'snapshots'
probe = art/'ordinary-app-ion-probe-20261118-02'
vendor = art/'ordinary-app-ion-vendor-20261118-01'
parent_vendor = art/'wifi-supplicant-vendor-20261118-02'
device = Path('device/samsung/gta3xlwifi')

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()

def read(path):
    return json.loads(path.read_text())

phase = sys.argv[1]
assert phase in {'policy','ota'}
work = art/f'runtime29-{phase}-selection-20261118-01'
work.mkdir()
before = base/('port-20261118-28' if phase=='policy' else 'port-20261118-29-policy')
after = base/('port-20261118-29-policy' if phase=='policy' else 'port-20261118-29')
audit = port/'tools/audit-port.py'
subprocess.run(['python3',audit,src,before,work/'source-before.json'],check=True)
assert not after.exists()
if phase == 'policy':
    proof = read(probe/'assertions.json')
    access = read(probe/'candidate-access/report.json')
    assert proof['passed'] and proof['candidate_assertions_and_constraints']==5881
    assert access['passed'] and access['policy_sha256']==sha(probe/'strict.policy')
    assert read(probe/'baseline-access/report.json')['passed']
    f = src/device/'sepolicy/private/gta3xlwifi_ion.te'
    original = f.read_text()
    assert 'untrusted_app_all' not in original
    updated = original + '''
# The retained Samsung Mali allocator opens ION in ordinary app processes.
# Restore only the read-side graphics interface on this legacy product.
allow { untrusted_app_all -runas_app } ion_device:chr_file { getattr open read ioctl map };
'''
else:
    old = read(parent_vendor/'report.json')
    new = read(vendor/'report.json')
    assert old['passed'] and new['passed']
    assert sha(vendor/'vendor.img')==new['vendor_sparse_sha256']
    assert sha(src/device/'prebuilt/vendor.img')==old['vendor_sparse_sha256']
    reference = read(parent_vendor/'after/report.json')['entries']
    selected = read(vendor/'after/report.json')['entries']
    assert reference.keys()==selected.keys()
    changed = {k for k in reference if reference[k]!=selected[k]}
    expected={'/etc/selinux/precompiled_sepolicy',
              '/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256'}
    assert changed==expected,changed
    for entry in changed:
        assert {k:v for k,v in reference[entry].items() if k not in {'sha256','size'}} == {
            k:v for k,v in selected[entry].items() if k not in {'sha256','size'}}
    assert selected['/etc/init/init.exynos7904.usb.rc']['sha256']==(
        '500d6fccbb990aad93a7de7fb4cf7e96d00702702bd021d18c9152d74e59ef1d')
    (work/'vendor-delta.json').write_text(json.dumps({'passed':True,
        'changed_contents':sorted(changed),'all_other_contents_and_metadata_unchanged':True,
        'previous_report_sha256':sha(parent_vendor/'report.json'),
        'candidate_report_sha256':sha(vendor/'report.json')},indent=2)+'\n')
    f = src/device/'releasetools.py'
    original = f.read_text()
    assert original.count(old['vendor_sparse_sha256'])==1
    updated = original.replace(old['vendor_sparse_sha256'],new['vendor_sparse_sha256'])
    compile(updated,str(f),'exec')
(work/'previous-source.txt').write_text(original)
projects = [r['project'] for r in read(before/'source-lock.json')]
try:
    f.write_text(updated)
    subprocess.run(['python3',port/'tools/capture-port.py','--parent-snapshot',before,src,after,*projects],check=True)
    subprocess.run(['python3',audit,src,after,after/'port-audit.json'],check=True)
except BaseException:
    f.write_text(original)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
