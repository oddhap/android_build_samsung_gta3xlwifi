#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot42: gate-split networking.

- releasetools.py: OTA kernel guard digest moves to the audited gate-split kernel.
- netd: kernel ABI 2; normal policy commits (SocketPolicyProjection::applyLocked)
  take the update lease with HOLD_UPDATE, which no longer closes the packet gate.
  suspendFrameworkClient keeps the gate-closing HOLD; every failure path still
  closes the lease (quarantine -> stop), which closes the gate in the kernel."""
import hashlib, json, subprocess
from pathlib import Path

src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261121-41', port/'snapshots/port-20261121-42'
work = art/'runtime42-source-selection-20261121-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
k = json.loads((art/'kernel-gate-split-build-20261121-01/report.json').read_text())
sel = json.loads((art/'runtime42-inputs-20261121-01/report.json').read_text())
old, new = k['previous_Image_sha256'], k['Image_sha256']
assert k['passed'] and sel['after']['Image'] == new
assert sha(src/'device/samsung/gta3xlwifi/prebuilt/Image') == new
f = src/'device/samsung/gta3xlwifi/releasetools.py'
original = f.read_text()
assert original.count(old) == 1 and new not in original
updated = original.replace(old, new)
compile(updated, str(f), 'exec')
edits = {f: (original, updated)}
N = src/'system/netd/server'
def edit(path, pairs):
    o = path.read_text(); u = o
    for a, b in pairs:
        assert u.count(a) == 1, (path, a)
        u = u.replace(a, b)
    edits[path] = (o, u)
edit(N/'linux/netfilter/gta3xlwifi_netpolicy.h', [
    ('#define GTA3XLWIFI_NETPOLICY_VERSION 1\n', '#define GTA3XLWIFI_NETPOLICY_VERSION 2\n'),
    ("#define GTA3XLWIFI_NETPOLICY_STATE   _IO('g', 0x53)\n",
     "#define GTA3XLWIFI_NETPOLICY_STATE   _IO('g', 0x53)\n"
     "/* v2: update lease that keeps the packet gate open. */\n"
     "#define GTA3XLWIFI_NETPOLICY_HOLD_UPDATE _IO('g', 0x64)\n")])
edit(N/'Gta3xlwifiNetpolicyLease.h', [
    ('    int hold();\n', '    int hold();\n    // Update lease for a normal commit; does not close the packet gate.\n    int holdForUpdate();\n')])
edit(N/'Gta3xlwifiNetpolicyLease.cpp', [
    ('int NetpolicyLease::release() {\n',
     'int NetpolicyLease::holdForUpdate() {\n'
     '    std::lock_guard<std::mutex> lock(mMutex);\n'
     '    return changeLocked(GTA3XLWIFI_NETPOLICY_HOLD_UPDATE, true);\n'
     '}\n'
     'int NetpolicyLease::release() {\n')])
edit(N/'Gta3xlwifiSocketPolicyProjection.cpp', [
    ('  // the old released state and perform NO ioctl or firewall operation.\n  r = mLease.hold();\n',
     '  // the old released state and perform NO ioctl or firewall operation.\n'
     '  // Gate-split (ABI 2): the update lease keeps the packet gate open; each\n'
     '  // family table swap is atomic and any failure below closes the lease.\n'
     '  r = mLease.holdForUpdate();\n')])
originals = work/'originals'
originals.mkdir()
for path, (o, u) in edits.items():
    (originals/(path.name + '.original')).write_text(o)
(work/'edits.json').write_text(json.dumps({str(p): {'before_sha256': hashlib.sha256(o.encode()).hexdigest(),
    'after_sha256': hashlib.sha256(u.encode()).hexdigest()} for p, (o, u) in edits.items()}, indent=2)+'\n')
(work/'kernel-digest.json').write_text(json.dumps({'kernel_before': old, 'kernel_after': new}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    for path, (o, u) in edits.items():
        path.write_text(u)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for path, (o, u) in edits.items():
        path.write_text(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
r = dict(sel)
p = art/'runtime42-inputs-20261121-01/report.json'
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p))
out = art/'runtime42-inputs-20261121-02'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot42 gate-split netd + kernel guard:', after)
