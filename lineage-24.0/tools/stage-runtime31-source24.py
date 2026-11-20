#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed snapshot31 changes on the synced lineage-24.0 tree.

policy: (1) NetworkStack uses AOSP's existing pre-U data-stall path instead of
        the BPF-map isUidNetworkingBlocked read when the product selected the
        legacy kernel 4.4 networking backend (b/326143935 fallback; no fake BPF);
        (2) grant system:firmware_load exactly to the observed firmware loaders
        enforced by the port kernel's firmware hook.
ota:    bind the OTA vendor guard to the strictly composed snapshot31 vendor.
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
parent_vendor = art/'ordinary-app-ion-vendor-20261118-01'
vendor = art/'firmware-policy-vendor-20261120-01'
device = Path('device/samsung/gta3xlwifi')
stack = Path('packages/modules/NetworkStack')
tracker = stack/'src/com/android/networkstack/netlink/TcpSocketTracker.java'

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
work = art/f'runtime31-{phase}-selection-20261120-03'
work.mkdir()
before = base/('port-20261120-31-sync' if phase == 'policy' else 'port-20261120-31-policy')
after = base/('port-20261120-31-policy' if phase == 'policy' else 'port-20261120-31')
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
edits = {}
if phase == 'policy':
    f = src/tracker
    original = f.read_text()
    old_import = 'import android.os.SystemClock;\n'
    new_import = 'import android.os.SystemClock;\nimport android.os.SystemProperties;\n'
    old_body = '''        public boolean shouldIgnoreTcpInfoForBlockedUids() {
            // Note b/326143935 - can trigger crash due to kernel bug / missing
            // feature on some T devices.
            return SdkLevel.isAtLeastU()'''
    new_body = '''        public boolean shouldIgnoreTcpInfoForBlockedUids() {
            // The gta3xlwifi legacy kernel 4.4 networking backend has no BPF
            // configuration map, so isUidNetworkingBlocked cannot be served.
            // Use the existing pre-U data-stall path instead of crashing.
            if (SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)) {
                return false;
            }
            // Note b/326143935 - can trigger crash due to kernel bug / missing
            // feature on some T devices.
            return SdkLevel.isAtLeastU()'''
    assert original.count(old_import) == 1 and original.count(old_body) == 1
    assert 'import android.os.SystemProperties;' not in original
    edits[f] = (original, original.replace(old_import, new_import).replace(old_body, new_body))
    te = src/device/'sepolicy/private/gta3xlwifi_firmware.te'
    assert not te.exists()
    edits[te] = (None, '''# The port kernel enforces system:firmware_load for direct firmware reads in
# the requesting process context, and for user-helper completion in the
# ueventd context. Android 17 defines the permission that Android 14 left
# unknown (and therefore allowed). Grant it only to the observed loaders:
# the camera HAL (FIMC-IS), the media codec HAL (MFC) and ueventd fallback.
# vendor_firmware_file is a vendor-only Samsung type that platform policy
# cannot name; vendor_file_type is its public attribute. The kernel only
# loads firmware from its fixed firmware search paths. hal_omx_server is
# exactly the vendor mediacodec domain (hal_codec2_server also has the
# platform software codec, which needs no firmware).
allow hal_camera_server vendor_file_type:system firmware_load;
allow hal_omx_server vendor_file_type:system firmware_load;
allow ueventd self:system firmware_load;
''')
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
(work/'edits.json').write_text(json.dumps({str(k): {'before_sha256': None if v[0] is None else
    hashlib.sha256(v[0].encode()).hexdigest(), 'after_sha256': hashlib.sha256(v[1].encode()).hexdigest()}
    for k, v in edits.items()}, indent=2)+'\n')
projects = [r['project'] for r in read(before/'source-lock.json')]
if phase == 'policy':
    assert str(stack) not in projects
    projects.append(str(stack))
try:
    for f, (_, updated) in edits.items():
        f.write_text(updated)
        if _ is None:
            subprocess.run(['git', '-C', str(src/device), 'add', '-N', str(f.relative_to(src/device))], check=True)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for f, (original, _) in edits.items():
        if original is None:
            subprocess.run(['git', '-C', str(src/device), 'rm', '-q', '--cached', '--ignore-unmatch',
                            str(f.relative_to(src/device))], check=False)
            f.unlink(missing_ok=True)
        else:
            f.write_text(original)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
print(f'PASS staged snapshot31 {phase}:', after)
