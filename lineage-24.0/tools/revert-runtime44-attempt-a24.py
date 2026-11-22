#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Revert failed snapshot44 attempt a back to exact snapshot43.

The product build stopped in post_process_props.py: non-ro property values are
limited to PROP_VALUE_MAX (91 bytes) and the first lineage.updater.uri was 108
bytes. Restores device.mk, releasetools.py and recovery_header_sync.cpp from the
recorded originals only if they equal the recorded snapshot44 results, audits
snapshot43 PASS, and keeps every attempt artifact/log under a *-failed-a name.
Nothing is deleted.
"""
import hashlib, json, subprocess
from pathlib import Path

T = Path('/srv/android/src/lineage-24.0-arm64')
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
L = Path('/srv/android/logs/lineage-24.0-arm64')
P = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
sha = lambda b: hashlib.sha256(b).hexdigest()
assert (L/'runtime44-product-build-20261121-01.exit').read_text().strip() == '1'
assert (L/'runtime44-orchestrator-20261121-01.exit').read_text().strip() == '1'
assert b'lineage.updater.uri cannot exceed 91 bytes' in (L/'runtime44-product-build-20261121-01.log').read_bytes()
work = A/'runtime44-source-selection-20261121-01'
edits = json.loads((work/'edits.json').read_text())
for name, e in edits.items():
    f = Path(name)
    assert sha(f.read_bytes()) in (e['after_sha256'], e['before_sha256']), name
    assert sha((work/'originals'/(f.name + '.original')).read_bytes()) == e['before_sha256'], name
for name in edits:
    f = Path(name)
    f.write_bytes((work/'originals'/(f.name + '.original')).read_bytes())
failed = 'failed-a'
out = A/('runtime44-revert-'+failed+'-20261121-01')
out.mkdir(exist_ok=True)
subprocess.run(['python3', P/'tools/audit-port.py', T, P/'snapshots/port-20261121-43', out/'source-after-revert.json'], check=True)
moves = [(P/'snapshots/port-20261121-44', P/('snapshots/port-20261121-44-'+failed)),
         (A/'runtime44-orchestrator-source-before.json', A/('runtime44-orchestrator-source-before-'+failed+'.json'))]
for d in ['runtime44-source-selection-20261121-01', 'runtime44-inputs-20261121-01', 'runtime44-devicemk-rebind-20261121-01',
          'runtime44-recovery-identity-host-20261121-01', 'runtime44-product-build-20261121-01']:
    moves.append((A/d, A/(d+'-'+failed)))
for n in ['runtime44-orchestrator-20261121-01', 'runtime44-product-build-20261121-01']:
    for ext in ['.log', '.exit']:
        moves.append((L/(n+ext), L/(n+'-'+failed+ext)))
for src, dst in moves:
    assert src.exists() and not dst.exists(), src
for src, dst in moves:
    src.rename(dst)
(out/'report.json').write_text(json.dumps({'passed': True, 'scope': __doc__, 'restored': list(edits),
    'moved': [[str(s), str(d)] for s, d in moves]}, indent=2)+'\n')
print('PASS reverted snapshot44 attempt a to exact snapshot43; artifacts kept as *-failed-a')
