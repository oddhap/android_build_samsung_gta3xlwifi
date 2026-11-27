#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot54: system_server file-descriptor leak (2026-11-27 soft reboot on build 53).

Gta3xlwifiStatsJournal.readKernelBootId() wrapped an Os.open() descriptor in
new FileInputStream(fd). On Android that constructor does not own the descriptor
(libcore isFdOwner=false), so try-with-resources never closed it. requireOwner()
reads boot_id on every journal operation, so system_server leaked one descriptor
per stats access until EMFILE (RLIMIT_NOFILE 32768) after about 3.7 days, and
PowerStatsStore then crashed system_server. Device probe (runtime54-fdleak):
old pattern 500 reads -> +500 fds, fixed pattern -> +0. Fix: Os.close(fd) in finally.

Parent is port-20261127-54-sync (snapshot53 patches on current lineage-24.0).
Prebuilts (kernel/vendor/dtbo) are unchanged from the build 53 selection.
No SELinux, vendor, kernel or other change."""
import hashlib, json, shutil, subprocess, sys
from pathlib import Path
src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261127-54-sync', port/'snapshots/port-20261127-54'
fixed = Path(sys.argv[1])  # uploaded runtime54-stats/Gta3xlwifiStatsJournal.java
work = art/'runtime54-source-selection-20261127-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert json.loads((work/'source-before.json').read_text())['passed']
assert not after.exists()
journal = src/'packages/modules/Connectivity/service/src/com/android/server/Gta3xlwifiStatsJournal.java'
OLD = '95e5cccd2493c451039f48e18303d58f232aef5309ab7bfbfd07a030b4c3dc3b'
NEW = 'd819492d68ab2d922a3caaf1e964ca0a9f8ecafc9eefa9bffb6f3d9f50f9b58d'
assert sha(journal) == OLD, sha(journal)
assert sha(fixed) == NEW, sha(fixed)
o, u = journal.read_text(), fixed.read_text()
assert u.count('Os.close(fd)') == o.count('Os.close(fd)') + 1
(work/'originals').mkdir()
shutil.copyfile(journal, work/'originals/Gta3xlwifiStatsJournal.java.original')
(work/'edits.json').write_text(json.dumps({str(journal): {'before_sha256': OLD, 'after_sha256': NEW}}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    journal.write_text(u)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    journal.write_text(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime53-inputs-20261123-02/report.json'
r = json.loads(p.read_text())
assert r['passed'] and r['original_rollback_copies_verified']
for name, digest in r['after'].items():
    assert sha(src/'device/samsung/gta3xlwifi/prebuilt'/name) == digest, name
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p), runtime_prebuilts_changed=False)
out = art/'runtime54-inputs-20261127-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot54 journal fd close:', after)
