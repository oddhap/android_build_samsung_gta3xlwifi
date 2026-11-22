#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Revert stopped snapshot45 attempt a back to exact snapshot44.

Build 44 showed physically that backuptool skips addon.d backup/restore in TWRP
("Incompatible ROM version": ro.lineage.version is only in system/product and
TWRP's /product is an empty directory). The build 45 product build was stopped
(TERM, exit 143) so snapshot45 can carry that fix too. Restores releasetools.py
from the recorded original only if it equals the recorded snapshot45 result,
audits snapshot44 PASS, and keeps every artifact/log under a *-failed-a name.
Nothing is deleted.
"""
import hashlib, json, subprocess, sys
from pathlib import Path

T = Path('/srv/android/src/lineage-24.0-arm64')
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
L = Path('/srv/android/logs/lineage-24.0-arm64')
P = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
sha = lambda b: hashlib.sha256(b).hexdigest()
assert (L/'runtime45-product-build-20261121-01.exit').read_text().strip() == '143'
work = A/'runtime45-source-selection-20261121-01'
edits = json.loads((work/'edits.json').read_text())
for name, e in edits.items():
    f = Path(name)
    assert sha(f.read_bytes()) in (e['after_sha256'], e['before_sha256']), name
    assert sha((work/'originals'/(f.name + '.original')).read_bytes()) == e['before_sha256'], name
for name in edits:
    f = Path(name)
    f.write_bytes((work/'originals'/(f.name + '.original')).read_bytes())
# Usage: [SUFFIX ORCHESTRATOR_LABEL] (default failed-a runtime45-orchestrator-20261121-02).
# Attempt b (orchestrator -03) was stopped after the physical TWRP test showed that
# blockdev --setro does not stop an rw vendor mount on this kernel and that TWRP
# creates /mnt/system (backuptool's system mount).
failed = sys.argv[1] if len(sys.argv) > 1 else 'failed-a'
orch = sys.argv[2] if len(sys.argv) > 2 else 'runtime45-orchestrator-20261121-02'
assert failed in ('failed-a', 'failed-b', 'failed-c') and orch.startswith('runtime45-orchestrator-20261121-')
out = A/('runtime45-revert-'+failed+'-20261121-01')
out.mkdir(exist_ok=True)
subprocess.run(['python3', P/'tools/audit-port.py', T, P/'snapshots/port-20261121-44', out/'source-after-revert.json'], check=True)
moves = [(P/'snapshots/port-20261121-45', P/('snapshots/port-20261121-45-'+failed)),
         (A/'runtime45-orchestrator-source-before.json', A/('runtime45-orchestrator-source-before-'+failed+'.json'))]
for d in ['runtime45-source-selection-20261121-01', 'runtime45-inputs-20261121-01', 'runtime45-product-build-20261121-01']:
    moves.append((A/d, A/(d+'-'+failed)))
for n in [orch, 'runtime45-product-build-20261121-01']:
    for ext in ['.log', '.exit']:
        moves.append((L/(n+ext), L/(n+'-'+failed+ext)))
for src, dst in moves:
    assert src.exists() and not dst.exists(), src
for src, dst in moves:
    src.rename(dst)
(out/'report.json').write_text(json.dumps({'passed': True, 'scope': __doc__, 'restored': list(edits),
    'moved': [[str(s), str(d)] for s, d in moves]}, indent=2)+'\n')
print('PASS reverted snapshot45 attempt to exact snapshot44; artifacts kept as *-' + failed)
