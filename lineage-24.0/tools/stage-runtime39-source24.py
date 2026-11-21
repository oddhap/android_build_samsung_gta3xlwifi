#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot39: recognize the owner-approved TWRP (choice a) in the OTA preflight helper.

On 2026-11-21 the owner approved changing the TWRP ramdisk crypto script so a
system patch month newer than the fixed recovery header month is accepted
(recovery partition SHA256 96b3de24...). The read-only OTA preflight helper
(recovery-header-sync) only recognizes exact known TWRP identities (SHA256 of the
image prefix with OS/SPL bytes 44..47 zeroed), so it would block installation.
Add exactly one identity: {40271888, 01e34bd1...}. The three previous identities
are kept so the verified backup remains installable. No other change; the helper
stays read-only and the OS/SPL word check is unchanged. Policy, vendor, kernel,
boot image unchanged from build 38.
"""
import hashlib, json, subprocess
from pathlib import Path

src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261121-38', port/'snapshots/port-20261121-39'
work = art/'runtime39-recovery-identity-selection-20261121-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
f = src/'device/samsung/gta3xlwifi/recovery-header-sync/recovery_header_sync.cpp'
assert sha(f) == '5aced3c99a33c8275562e989e2004dd3389cacc2c980e4386e917c6b101ad4fe'
o = f.read_text()
anchor = '    {40275984, "5eb6d0f8fbb75f08d7156d3de1118fc429eff44543fd61e6a7c1b8c99dc21239"},\n};\n'
NEW = ('    {40275984, "5eb6d0f8fbb75f08d7156d3de1118fc429eff44543fd61e6a7c1b8c99dc21239"},\n'
       '    // Owner-approved 2026-11-21 (choice a): crypto script accepts a system patch\n'
       '    // month newer than the fixed header month; kernel and DTBO unchanged.\n'
       '    {40271888, "01e34bd1051135bf4b7e8a024bf28f70499f742cdc842d8434ee2037cf59c8e3"},\n'
       '};\n')
assert o.count(anchor) == 1 and '01e34bd1' not in o
u = o.replace(anchor, NEW)
edits = {f: (o, u)}
originals = work/'originals'
originals.mkdir()
(originals/(f.name + '.original')).write_text(o)
(work/'edits.json').write_text(json.dumps({str(f): {'before_sha256': hashlib.sha256(o.encode()).hexdigest(),
    'after_sha256': hashlib.sha256(u.encode()).hexdigest()}}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    f.write_text(u)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    f.write_text(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime38-inputs-20261121-01/report.json'
r = json.loads(p.read_text())
assert r['passed']
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p), runtime_prebuilts_changed=False)
out = art/'runtime39-inputs-20261121-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot39 recovery identity for owner-approved TWRP:', after)
