#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Revert a failed snapshot40 attempt back to exact snapshot39 (argv[1] = suffix).

Attempt a: Kati stopped (device.mk PRODUCT_BUILD_PRODUCT_IMAGE := true).
Attempt b: ninja stopped: stale out/.../system/product symlink from the old layout
(fixed in attempt c by m installclean before the build).

Restores BoardConfig.mk and fstab.exynos7904 from the recorded originals only if
they still equal the recorded snapshot40 results, audits snapshot39 PASS, and
preserves every attempt artifact/log under a *-failed-a name. Nothing is deleted.
"""
import hashlib, json, subprocess, sys
from pathlib import Path

T = Path('/srv/android/src/lineage-24.0-arm64')
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
L = Path('/srv/android/logs/lineage-24.0-arm64')
P = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
sha = lambda b: hashlib.sha256(b).hexdigest()
assert (L/'runtime40-product-build-20261121-01.exit').read_text().strip() == '1'
assert (L/'runtime40-orchestrator-20261121-01.exit').read_text().strip() == '1'
work = A/'runtime40-product-in-system-selection-20261121-01'
edits = json.loads((work/'edits.json').read_text())
for name, e in edits.items():
    f = Path(name)
    assert sha(f.read_bytes()) in (e['after_sha256'], e['before_sha256']), name  # rerun after partial run
    o = (work/'originals'/(f.name + '.original')).read_bytes()
    assert sha(o) == e['before_sha256'], name
for name in edits:
    f = Path(name)
    f.write_bytes((work/'originals'/(f.name + '.original')).read_bytes())
failed = sys.argv[1]
assert failed in ('failed-a', 'failed-b', 'failed-c', 'failed-d')
out = A/('runtime40-revert-'+failed+'-20261121-01')
out.mkdir(exist_ok=True)
subprocess.run(['python3', P/'tools/audit-port.py', T, P/'snapshots/port-20261121-39', out/'source-after-revert.json'], check=True)
moves = [(P/'snapshots/port-20261121-40', P/('snapshots/port-20261121-40-'+failed))]
for d in ['runtime40-product-in-system-selection-20261121-01', 'runtime40-inputs-20261121-01',
          'runtime40-boardconfig-rebind-20261121-01', 'runtime40-devicemk-rebind-20261121-01',
          'runtime40-product-build-20261121-01']:
    if (A/d).exists() or d != 'runtime40-devicemk-rebind-20261121-01':
        moves.append((A/d, A/(d+'-'+failed)))
for n in ['runtime40-orchestrator-20261121-01', 'runtime40-product-build-20261121-01']:
    for ext in ['.log', '.exit']:
        moves.append((L/(n+ext), L/(n+'-'+failed+ext)))
for src, dst in moves:
    assert src.exists() and not dst.exists(), src
for src, dst in moves:
    src.rename(dst)
(out/'report.json').write_text(json.dumps({'passed': True, 'scope': __doc__, 'restored': list(edits),
    'moved': [[str(s), str(d)] for s, d in moves]}, indent=2)+'\n')
print('PASS reverted snapshot40 attempt to exact snapshot39; artifacts kept as *-'+failed)
