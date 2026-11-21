#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind host proofs that hash-bind BoardConfig.mk to the snapshot40 file.

Snapshot40 only removes the product image (BOARD_PRODUCTIMAGE_PARTITION_SIZE,
BOARD_PRODUCTIMAGE_FILE_SYSTEM_TYPE) and sets TARGET_COPY_OUT_PRODUCT :=
system/product with a comment. Require that each proof's BoardConfig.mk digest
is the snapshot39 original and that the current file is exactly that original
with only the recorded replacements applied. All other bound sources must still
match. Proof results are carried over unchanged; nothing is re-tested.
"""
import hashlib, json, sys
from pathlib import Path

A = Path('/srv/android/artifacts/lineage-24.0-arm64')
T = Path('/srv/android/src/lineage-24.0-arm64')
O = A/sys.argv[1]
O.mkdir()
rel = 'device/samsung/gta3xlwifi/BoardConfig.mk'
sha = lambda b: hashlib.sha256(b).hexdigest()
work = A/'runtime40-product-in-system-selection-20261121-01'
original = (work/'originals/BoardConfig.mk.original').read_bytes()
current = (T/rel).read_bytes()
e = json.loads((work/'edits.json').read_text())[str(T/rel)]
assert sha(original) == e['before_sha256'] and sha(current) == e['after_sha256']
expected = original
for old, new in json.loads((work/'replacements.json').read_text())['BoardConfig.mk']:
    assert expected.count(old.encode()) == 1
    expected = expected.replace(old.encode(), new.encode())
assert expected == current and b'PRODUCTIMAGE' not in current
assert b'\nTARGET_COPY_OUT_PRODUCT := system/product\n' in current
proofs = ['mapper-regression-binding.json', 'touch-host-proof.json', 'aconfig-host-report.json']
for name in proofs:
    p = A/'runtime38-boardconfig-rebind-20261121-02'/name
    d = json.loads(p.read_text())
    assert d['passed'] and d['source_sha256'][rel] == sha(original), name
    for other, h in d['source_sha256'].items():
        assert other == rel or sha((T/other).read_bytes()) == h, other
    d['source_sha256'][rel] = sha(current)
    d.update(boardconfig_rebound_from=str(p), boardconfig_rebound_from_sha256=sha(p.read_bytes()),
             boardconfig_only_change='Product image removed; TARGET_COPY_OUT_PRODUCT := system/product (snapshot40)',
             boardconfig_rebinding_scope=__doc__)
    (O/name).write_text(json.dumps(d, indent=2)+'\n')
(O/'report.json').write_text(json.dumps({'passed': True, 'boardconfig_before_sha256': sha(original),
    'boardconfig_after_sha256': sha(current)}, indent=2)+'\n')
print('PASS rebound BoardConfig.mk-bound proofs; only the product-image lines changed')
