#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot36: wait for the real legacy-backend unblock commit on app resume.

ActivityManager blocks a resuming app's main thread until NetworkPolicyManager
reports that the UID's firewall rules for the new process state are committed
(procStateSeq), but only for network_access_timeout_ms (200 ms, sized for BPF
map writes). On SM-T510 the legacy backend commits every rule change as a
complete netd policy frame (held barrier, iptables replace/verify, kernel
images), measured at ~0.4-1 s per foreground transition. The app therefore ran
while still blocked: its first DNS/TCP attempts failed, SYNs were dropped into
exponential backoff (SYN_SENT up to ~2 min) and ConnectivityManager reported
BLOCKED with no later callback for apps that do not declare
onBlockedStatusChanged. Only the DEFAULT wait budget changes, and only when the
legacy backend is selected; the DeviceConfig override, the procStateSeq
protocol and all enforcement stay unchanged. Policy, vendor, kernel unchanged.
"""
import hashlib, json, subprocess
from pathlib import Path

src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261120-35', port/'snapshots/port-20261120-36'
work = art/'runtime36-netaccess-selection-20261120-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
f = src/'frameworks/base/services/core/java/com/android/server/am/ActivityManagerConstants.java'
original = f.read_text()
anchor = '    private static final long DEFAULT_NETWORK_ACCESS_TIMEOUT_MS = 200; // 0.2 sec\n'
assert original.count(anchor) == 1 and 'gta3xlwifi' not in original
assert original.count('import android.os.SystemProperties;\n') == 1
replacement = '''    // SM-T510 legacy (non-BPF) networking backend: every firewall rule change is
    // committed as a complete netd policy frame (~0.4-1 s), not a BPF map write.
    // Wait for that real commit so a resumed app never runs while its rules still
    // block it. The DeviceConfig override and procStateSeq protocol are unchanged.
    private static final long DEFAULT_NETWORK_ACCESS_TIMEOUT_MS =
            SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)
                    ? 2000 : 200; // 2 s legacy backend, else 0.2 sec
'''
updated = original.replace(anchor, replacement)
(work/'ActivityManagerConstants.java.original').write_text(original)
(work/'edits.json').write_text(json.dumps({str(f): {'before_sha256': hashlib.sha256(original.encode()).hexdigest(),
    'after_sha256': hashlib.sha256(updated.encode()).hexdigest()}}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    f.write_text(updated)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    f.write_text(original)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime35-inputs-20261120-01/report.json'
r = json.loads(p.read_text())
assert r['passed']
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p), runtime_prebuilts_changed=False)
out = art/'runtime36-inputs-20261120-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot36 legacy-backend network-access wait:', after)
