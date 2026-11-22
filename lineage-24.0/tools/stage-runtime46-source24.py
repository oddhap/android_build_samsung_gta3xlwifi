#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed snapshot46 change on top of snapshot45.

policy: physical build-44 OTA test: the LineageOS Updater (domain updater_app,
        device/lineage/sepolicy) is denied the retained Linux 4.4 ION read API, so
        HWUI aborts (drawRenderNode with no surface) and Settings > System >
        Updater cannot be used. Owner approved (2026-11-22): add updater_app to the
        scoped ION read rule (r_file_perms, no write), exactly like gmscore_app.
ota:    bind the OTA vendor guard to the strictly composed snapshot46 vendor.
"""
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
parent_vendor = art/'gmsion-vendor-20261121-01'
vendor = art/'updion-vendor-20261122-01'
device = Path('device/samsung/gta3xlwifi')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read(path):
    return json.loads(path.read_text())


phase = sys.argv[1]
assert phase in {'policy', 'ota'}
work = art/f'runtime46-{phase}-selection-20261122-01'
work.mkdir()
before = base/('port-20261121-45' if phase == 'policy' else 'port-20261122-46-policy')
after = base/('port-20261122-46-policy' if phase == 'policy' else 'port-20261122-46')
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
edits = {}
if phase == 'policy':
    ion = src/device/'sepolicy/private/gta3xlwifi_ion.te'
    original = ion.read_text()
    old = 'allow { priv_app_all gmscore_app } ion_device:chr_file r_file_perms;\n'
    assert original.count(old) == 1 and 'updater_app' not in original
    add = old + ('\n# Physical build-44 OTA test: the LineageOS Updater (updater_app) fails\n'
                 '# ion_open, so HWUI aborts and the Updater cannot be used. Owner approved\n'
                 '# (2026-11-22) the same scoped read API as gmscore_app.\n'
                 'allow updater_app ion_device:chr_file r_file_perms;\n')
    edits[ion] = (original, original.replace(old, add))
else:
    old = read(parent_vendor/'report.json')
    new = read(vendor/'report.json')
    assert old['passed'] and new['passed']
    assert sha(vendor/'vendor.img') == new['vendor_sparse_sha256']
    assert sha(src/device/'prebuilt/vendor.img') == old['vendor_sparse_sha256']
    reference = read(parent_vendor/'after/report.json')['entries']
    selected = read(vendor/'after/report.json')['entries']
    assert set(reference) <= set(selected)
    changed = {k for k in reference if reference[k] != selected[k]}
    expected = {'/etc/selinux/precompiled_sepolicy',
                '/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256'}
    assert changed == expected, changed
    added = set(selected) - set(reference)
    assert added == set(), added
    for entry in changed:
        assert {k: v for k, v in reference[entry].items() if k not in {'sha256', 'size'}} == {
            k: v for k, v in selected[entry].items() if k not in {'sha256', 'size'}}
    assert selected['/etc/init/init.exynos7904.usb.rc']['sha256'] == reference['/etc/init/init.exynos7904.usb.rc']['sha256']
    (work/'vendor-delta.json').write_text(json.dumps({'passed': True,
        'changed_contents': sorted(changed), 'added_paths': sorted(added), 'all_other_contents_and_metadata_unchanged': True,
        'previous_report_sha256': sha(parent_vendor/'report.json'),
        'candidate_report_sha256': sha(vendor/'report.json')}, indent=2)+'\n')
    f = src/device/'releasetools.py'
    original = f.read_text()
    assert original.count(old['vendor_sparse_sha256']) == 1
    updated = original.replace(old['vendor_sparse_sha256'], new['vendor_sparse_sha256'])
    compile(updated, str(f), 'exec')
    edits[f] = (original, updated)
originals = work/'originals'
originals.mkdir()
for f, (o, _) in edits.items():
    (originals/f.name).write_text(o)
(work/'edits.json').write_text(json.dumps({str(k): {'before_sha256': hashlib.sha256(v[0].encode()).hexdigest(),
    'after_sha256': hashlib.sha256(v[1].encode()).hexdigest()} for k, v in edits.items()}, indent=2)+'\n')
projects = [r['project'] for r in read(before/'source-lock.json')]
try:
    for f, (_, updated) in edits.items():
        f.write_text(updated)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for f, (original, _) in edits.items():
        f.write_text(original)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
print(f'PASS staged snapshot46 {phase}:', after)
