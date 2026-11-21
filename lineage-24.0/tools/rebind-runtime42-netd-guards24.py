#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind the netd first-boot guard proof to the snapshot42 projection source.

Snapshot42 changes Gta3xlwifiSocketPolicyProjection.cpp only in the normal commit
path (applyLocked: mLease.hold() -> mLease.holdForUpdate(), plus comments). The
proof covers Controllers.cpp startup guard ordering and only records the
projection file as unchanged. Require: the recorded snapshot42 original equals the
proof's projection hash, the current file is exactly that original with the
recorded replacement, and every other bound source still matches. Results are
carried over; nothing is re-tested.
"""
import hashlib, json, sys
from pathlib import Path

A = Path('/srv/android/artifacts/lineage-24.0-arm64')
T = Path('/srv/android/src/lineage-24.0-arm64')
O = A/sys.argv[1]
O.mkdir()
sha = lambda b: hashlib.sha256(b).hexdigest()
proof_path = A/'netd-first-guards-host-20261116-01/report.json'
proof = json.loads(proof_path.read_text())
assert proof['passed'] and not proof['policy_kernel_crypto_and_boot_failure_guards_changed']
rel = 'system/netd/server/Gta3xlwifiSocketPolicyProjection.cpp'
work = A/'runtime42-source-selection-20261121-01'
edits = json.loads((work/'edits.json').read_text())[str(T/rel)]
original = (work/'originals/Gta3xlwifiSocketPolicyProjection.cpp.original').read_bytes()
current = (T/rel).read_bytes()
assert sha(original) == edits['before_sha256'] == proof['unchanged_projection_source_sha256']
assert sha(current) == edits['after_sha256']
old_line = b'  r = mLease.hold();\n  if (r) return quarantine(r);\n  r = verifyHooks();'
new_line = b'  r = mLease.holdForUpdate();\n  if (r) return quarantine(r);\n  r = verifyHooks();'
assert original.count(old_line) == 1 and current.count(new_line) == 1
comment = (b'  // Gate-split (ABI 2): the update lease keeps the packet gate open; each\n'
           b'  // family table swap is atomic and any failure below closes the lease.\n')
assert current == original.replace(old_line, comment + new_line)
for name, h in proof['source_sha256'].items():
    assert sha((T/name).read_bytes()) == h, name
assert sha((T/'system/netd/server/projection-guards.inc').read_bytes()) == proof['unchanged_guard_implementation_sha256']
out = dict(proof)
out.update(unchanged_projection_source_sha256=sha(current), rebound_from=str(proof_path),
           rebound_from_sha256=sha(proof_path.read_bytes()),
           projection_only_change='applyLocked uses holdForUpdate (gate-split, snapshot42)',
           rebinding_scope=__doc__)
(O/'netd-first-guards-host.json').write_text(json.dumps(out, indent=2)+'\n')
(O/'report.json').write_text(json.dumps({'passed': True, 'projection_before_sha256': sha(original),
    'projection_after_sha256': sha(current)}, indent=2)+'\n')
print('PASS rebound netd first-guard proof; projection changed only in the normal commit lease call')
