#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed snapshot34 changes on top of installed snapshot33.

policy: (1) owner-observed invisible permission dialogs: permissioncontroller_app
        (and mediaprovider, plus owner-requested mediaserver) are denied the
        retained Linux 4.4 ION read API; add them to the scoped ION read rule.
        (2) the HIDL-only Bluetooth audio shim sources (device/.../btaudio),
        already placed by build-btaudio-shim24.sh, are verified and captured.
ota:    bind the OTA vendor guard to the strictly composed snapshot32 vendor.
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
parent_vendor = art/'camera-policy-vendor-20261120-01'
vendor = art/'btaudio-vendor-20261120-01'
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
work = art/f'runtime34-{phase}-selection-20261120-01'
work.mkdir()
before = base/('port-20261120-33' if phase == 'policy' else 'port-20261120-34-policy')
after = base/('port-20261120-34-policy' if phase == 'policy' else 'port-20261120-34')
audit = port/'tools/audit-port.py'
if phase == 'policy':
    # The shim is present as intent-to-add from build-btaudio-shim24.sh; verify it
    # exactly against the staged report (audit vs snapshot33 differs only by it).
    stage = Path('/srv/android/ports/lineage-24.0-arm64/btaudio-shim24-20261120-04')
    staged_files = {k[len('btaudio/'):]: v for k, v in read(stage/'report.json')['files_sha256'].items()}
    shim_files = {str(p.relative_to(src/device/'btaudio')): sha(p) for p in sorted((src/device/'btaudio').rglob('*')) if p.is_file()}
    assert shim_files == staged_files, 'device btaudio differs from staged shim'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=phase != 'policy')
assert not after.exists()
edits = {}
if phase == 'policy':
    ion = src/device/'sepolicy/private/gta3xlwifi_ion.te'
    original = ion.read_text()
    old = 'allow cameraserver ion_device:chr_file r_file_perms;\n'
    assert original.count(old) == 1 and 'permissioncontroller_app' not in original
    add = old + ('\n# Physical build-33 tests: the permission dialog (permissioncontroller_app)\n'
                 '# and DownloadProvider (mediaprovider) fail ion_open, so their HWUI never\n'
                 '# draws; mediaserver (NuPlayer) probes it too (owner requested).\n'
                 'allow { permissioncontroller_app mediaprovider mediaserver } ion_device:chr_file r_file_perms;\n')
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
                '/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256',
                '/etc/audio_policy_configuration.xml'}
    assert changed == expected, changed
    added = set(selected) - set(reference)
    assert added == {'/lib/hw/audio.bluetooth.exynos7904.so', '/etc/vintf/manifest/gta3xlwifi_btaudio.xml',
                     '/etc/bluetooth_audio_policy_configuration.xml'}, added
    for entry in changed:
        assert {k: v for k, v in reference[entry].items() if k not in {'sha256', 'size'}} == {
            k: v for k, v in selected[entry].items() if k not in {'sha256', 'size'}}
    assert selected['/etc/init/init.exynos7904.usb.rc']['sha256'] == (
        '500d6fccbb990aad93a7de7fb4cf7e96d00702702bd021d18c9152d74e59ef1d')
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
print(f'PASS staged snapshot34 {phase}:', after)
