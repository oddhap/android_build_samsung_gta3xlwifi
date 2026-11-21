#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot43: gate-split via HOLD argument (build 42's 0x6764 ioctl was denied by the
netd SELinux xperm list; netd quarantined fail-closed and system_server could not start).

- netd: kernel ABI 2 header defines GTA3XLWIFI_NETPOLICY_HOLD_UPDATE_ARG; holdForUpdate()
  issues HOLD (0x6751, already allowed) with that argument, same error handling as
  commandLocked (any deviation closes the lease, i.e. closes the gate).
- releasetools.py: OTA kernel guard digest moves to the gate-split -02 kernel.
No SELinux, vendor or other change."""
import hashlib, json, subprocess
from pathlib import Path
src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261121-42', port/'snapshots/port-20261121-43'
work = art/'runtime43-source-selection-20261121-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
k = json.loads((art/'kernel-gate-split-build-20261121-02/report.json').read_text())
sel = json.loads((art/'runtime43-inputs-20261121-01/report.json').read_text())
old, new = k['previous_Image_sha256'], k['Image_sha256']
assert k['passed'] and sel['after']['Image'] == new
assert sha(src/'device/samsung/gta3xlwifi/prebuilt/Image') == new
edits = {}
def edit(path, pairs):
    o = path.read_text(); u = o
    for a, b in pairs:
        assert u.count(a) == 1, (path, a)
        u = u.replace(a, b)
    edits[path] = (o, u)
edit(src/'device/samsung/gta3xlwifi/releasetools.py', [(old, new)])
compile(edits[src/'device/samsung/gta3xlwifi/releasetools.py'][1], 'releasetools.py', 'exec')
N = src/'system/netd/server'
edit(N/'linux/netfilter/gta3xlwifi_netpolicy.h', [
    ("/* v2: update lease that keeps the packet gate open. */\n#define GTA3XLWIFI_NETPOLICY_HOLD_UPDATE _IO('g', 0x64)\n",
     "/* v2: HOLD with this argument takes the update lease WITHOUT closing the packet gate. */\n#define GTA3XLWIFI_NETPOLICY_HOLD_UPDATE_ARG 1UL\n")])
edit(N/'Gta3xlwifiNetpolicyLease.cpp', [
    ('int NetpolicyLease::holdForUpdate() {\n'
     '    std::lock_guard<std::mutex> lock(mMutex);\n'
     '    return changeLocked(GTA3XLWIFI_NETPOLICY_HOLD_UPDATE, true);\n'
     '}\n',
     'int NetpolicyLease::holdForUpdate() {\n'
     '    std::lock_guard<std::mutex> lock(mMutex);\n'
     '    if (mFd < 0) return -ENOTCONN;\n'
     '    int result;\n'
     '    // Same ioctl number as HOLD (existing SELinux xperm); the argument selects\n'
     '    // the update lease that keeps the packet gate open.\n'
     '    do { result = ioctl(mFd, GTA3XLWIFI_NETPOLICY_HOLD, GTA3XLWIFI_NETPOLICY_HOLD_UPDATE_ARG); }\n'
     '    while (result < 0 && errno == EINTR);\n'
     '    if (result != 0) {\n'
     '        const int error = result < 0 ? (errno ? -errno : -EIO) : -EPROTO;\n'
     '        closeLocked();  // Owner close in the private driver rearms the barrier.\n'
     '        return error;\n'
     '    }\n'
     '    bool actual = false;\n'
     '    result = stateLocked(&actual);\n'
     '    if (result) return result;\n'
     '    if (!actual) { closeLocked(); return -EPROTO; }\n'
     '    return 0;\n'
     '}\n')])
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
p = art/'runtime43-inputs-20261121-01/report.json'
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p))
out = art/'runtime43-inputs-20261121-02'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot43 gate-split HOLD-argument netd + kernel guard:', after)
