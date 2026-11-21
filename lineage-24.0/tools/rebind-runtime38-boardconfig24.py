#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind host proofs that hash-bind BoardConfig.mk to the snapshot38 file.

Snapshot38 only inserts the fixed BOOT_SECURITY_PATCH block after the reviewed
BOARD_MKBOOTIMG_ARGS anchor. Require that each proof's old BoardConfig.mk digest
is the snapshot37 original and that the current file is exactly that original
with only the recorded block inserted (comments plus one BOOT_SECURITY_PATCH
assignment). All other bound sources must still match. Proof results are
carried over unchanged; nothing is re-tested.
"""
import hashlib, json, sys
from pathlib import Path

A = Path('/srv/android/artifacts/lineage-24.0-arm64')
T = Path('/srv/android/src/lineage-24.0-arm64')
O = A/sys.argv[1]
O.mkdir()
rel = 'device/samsung/gta3xlwifi/BoardConfig.mk'
sha = lambda b: hashlib.sha256(b).hexdigest()
work = A/'runtime38-bootspl-selection-20261121-01'
original = (work/'originals/BoardConfig.mk.original').read_bytes()
current = (T/rel).read_bytes()
e = json.loads((work/'edits.json').read_text())[str(T/rel)]
assert sha(original) == e['before_sha256'] and sha(current) == e['after_sha256']
anchor = (b'BOARD_MKBOOTIMG_ARGS := --header_version 1 --kernel_offset 0x00008000 --ramdisk_offset 0x01000000 '
          b'--tags_offset 0x00000100 --board SRPSA25A005KU\n')
i = original.index(anchor) + len(anchor)
assert original.count(anchor) == 1 and current.startswith(original[:i]) and current.endswith(original[i:])
inserted = current[i:len(current)-len(original[i:])].decode()
assert inserted == json.loads((work/'inserted.json').read_text())['BoardConfig.mk']
lines = inserted.splitlines()
assert all(l.startswith('#') for l in lines[:-1]) and lines[-1] == 'BOOT_SECURITY_PATCH := 2026-11-01', inserted
proofs = [('aconfig-cache-host-20261117-03/mapper-regression-binding.json', 'mapper-regression-binding.json'),
          ('runtime33-touch-kernel-rebind-20261120-01/touch-host-proof.json', 'touch-host-proof.json'),
          ('aconfig-cache-host-runtime31-20261120-01/report.json', 'aconfig-host-report.json')]
for proof_rel, name in proofs:
    p = A/proof_rel
    d = json.loads(p.read_text())
    assert d['passed'] and d['source_sha256'][rel] == sha(original), proof_rel
    for other, h in d['source_sha256'].items():
        assert other == rel or sha((T/other).read_bytes()) == h, other
    d['source_sha256'][rel] = sha(current)
    d.update(boardconfig_rebound_from=str(p), boardconfig_rebound_from_sha256=sha(p.read_bytes()),
             boardconfig_only_change='Fixed BOOT_SECURITY_PATCH block (snapshot38)', boardconfig_rebinding_scope=__doc__)
    (O/name).write_text(json.dumps(d, indent=2)+'\n')
(O/'report.json').write_text(json.dumps({'passed': True, 'inserted_block': inserted,
    'boardconfig_before_sha256': sha(original), 'boardconfig_after_sha256': sha(current)}, indent=2)+'\n')
print('PASS rebound BoardConfig.mk-bound proofs; only the BOOT_SECURITY_PATCH block was inserted')
