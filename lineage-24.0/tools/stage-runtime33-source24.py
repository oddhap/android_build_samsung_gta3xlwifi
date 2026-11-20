#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot33: bind the OTA kernel guard in releasetools.py to the audited
netpolicy-flush kernel. The guard stays; only its expected kernel digest moves
from the UID-receipt kernel to the selected, audited successor."""
import hashlib, json, subprocess
from pathlib import Path

src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261120-32', port/'snapshots/port-20261120-33'
work = art/'runtime33-ota-kernel-selection-20261120-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
k = json.loads((art/'kernel-netpolicy-flush-build-20261120-01/report.json').read_text())
sel = json.loads((art/'runtime33-inputs-20261120-01/report.json').read_text())
old, new = k['previous_Image_sha256'], k['Image_sha256']
assert k['passed'] and sel['after']['Image'] == new
assert sha(src/'device/samsung/gta3xlwifi/prebuilt/Image') == new
f = src/'device/samsung/gta3xlwifi/releasetools.py'
original = f.read_text()
assert original.count(old) == 1 and new not in original
updated = original.replace(old, new)
compile(updated, str(f), 'exec')
(work/'releasetools.py.original').write_text(original)
(work/'edits.json').write_text(json.dumps({str(f): {'before_sha256': hashlib.sha256(original.encode()).hexdigest(),
    'after_sha256': hashlib.sha256(updated.encode()).hexdigest(), 'kernel_before': old, 'kernel_after': new}}, indent=2)+'\n')
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
r = dict(sel)
p = art/'runtime33-inputs-20261120-01/report.json'
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p))
out = art/'runtime33-inputs-20261120-02'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot33 kernel guard:', after)
