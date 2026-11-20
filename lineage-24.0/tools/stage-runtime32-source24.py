#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed snapshot32 changes on top of installed snapshot31.

policy: (1) physical build-31 camera test: preview opens but cameraserver
        cannot read the retained Linux 4.4 ION device ("Can't dequeue next
        output buffer", EIO; avc read cameraserver ion_device). Add
        cameraserver to the existing scoped ION read rule.
        (2) the abox audio DSP firmware (AP_AUDIO_SLSI.bin,
        APBargeIn_AUDIO_SLSI.bin) is requested from a kernel worker in the
        kernel context and is denied system:firmware_load. Grant kernel the
        load from vendor files only (the kernel firmware search path).
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
parent_vendor = art/'firmware-policy-vendor-20261120-01'
vendor = art/'camera-policy-vendor-20261120-01'
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
work = art/f'runtime32-{phase}-selection-20261120-01'
work.mkdir()
before = base/('port-20261120-31' if phase == 'policy' else 'port-20261120-32-policy')
after = base/('port-20261120-32-policy' if phase == 'policy' else 'port-20261120-32')
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
edits = {}
if phase == 'policy':
    ion = src/device/'sepolicy/private/gta3xlwifi_ion.te'
    original = ion.read_text()
    old = 'allow { system_server mediaswcodec platform_app priv_app system_app } ion_device:chr_file r_file_perms;\n'
    assert original.count(old) == 1 and 'cameraserver' not in original
    add = old + ('\n# Physical build-31 camera test: cameraserver maps legacy Gralloc camera\n'
                 '# buffers through the retained ION read API and fails with EIO when denied.\n'
                 'allow cameraserver ion_device:chr_file r_file_perms;\n')
    edits[ion] = (original, original.replace(old, add))
    fw = src/device/'sepolicy/private/gta3xlwifi_firmware.te'
    original = fw.read_text()
    tail = 'allow ueventd self:system firmware_load;\n'
    assert original.endswith(tail) and 'allow kernel' not in original
    edits[fw] = (original, original + ('# Physical build-31 boot: abox requests the audio DSP firmware from a\n'
                                       '# kernel worker, so the hook checks the kernel context itself.\n'
                                       'allow kernel vendor_file_type:system firmware_load;\n'))
else:
    old = read(parent_vendor/'report.json')
    new = read(vendor/'report.json')
    assert old['passed'] and new['passed']
    assert sha(vendor/'vendor.img') == new['vendor_sparse_sha256']
    assert sha(src/device/'prebuilt/vendor.img') == old['vendor_sparse_sha256']
    reference = read(parent_vendor/'after/report.json')['entries']
    selected = read(vendor/'after/report.json')['entries']
    assert reference.keys() == selected.keys()
    changed = {k for k in reference if reference[k] != selected[k]}
    expected = {'/etc/selinux/precompiled_sepolicy',
                '/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256'}
    assert changed == expected, changed
    for entry in changed:
        assert {k: v for k, v in reference[entry].items() if k not in {'sha256', 'size'}} == {
            k: v for k, v in selected[entry].items() if k not in {'sha256', 'size'}}
    assert selected['/etc/init/init.exynos7904.usb.rc']['sha256'] == (
        '500d6fccbb990aad93a7de7fb4cf7e96d00702702bd021d18c9152d74e59ef1d')
    (work/'vendor-delta.json').write_text(json.dumps({'passed': True,
        'changed_contents': sorted(changed), 'all_other_contents_and_metadata_unchanged': True,
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
print(f'PASS staged snapshot32 {phase}:', after)
