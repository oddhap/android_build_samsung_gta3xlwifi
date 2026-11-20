#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind host proofs that hash-bind device.mk to the snapshot35 device.mk.

Snapshot35 only inserts the Bluetooth profile property block. Require that each
proof's old device.mk digest is the snapshot34 file and that the current file is
exactly that file with the block inserted after the reviewed anchor. Proof
results are carried over unchanged; nothing is re-tested.
"""
import hashlib, json, sys
from pathlib import Path

A = Path('/srv/android/artifacts/lineage-24.0-arm64')
T = Path('/srv/android/src/lineage-24.0-arm64')
O = A/sys.argv[1]
O.mkdir()
rel = 'device/samsung/gta3xlwifi/device.mk'
sha = lambda b: hashlib.sha256(b).hexdigest()
work = A/'runtime35-bt-profiles-selection-20261120-01'
original = (work/'device.mk.original').read_bytes()
current = (T/rel).read_bytes()
edits = json.loads((work/'edits.json').read_text())
(e,) = edits.values()
assert sha(original) == e['before_sha256'] and sha(current) == e['after_sha256']
anchor = b'    ro.product.product.cpu.abilist32=armeabi-v7a,armeabi\n'
i = original.index(anchor) + len(anchor)
assert current.startswith(original[:i]) and current.endswith(original[i:])
inserted = current[i:len(current)-len(original[i:])].decode()
assert all(l == '' or l.startswith('#') or l.startswith('PRODUCT_PRODUCT_PROPERTIES += \\') or
           l.strip().startswith('bluetooth.profile.') for l in inserted.splitlines()), inserted
for proof_rel, name in [('runtime31-host-proof-rebind-20261120-02/ui-host-proof.json', 'ui-host-proof.json'),
                        ('bpf-kernel-actual-host-20261118-27/report.json', 'bpf-kernel-actual-host-report.json')]:
    p = A/proof_rel
    d = json.loads(p.read_text())
    assert d['passed'] and d['source_sha256'][rel] == sha(original), proof_rel
    d['source_sha256'][rel] = sha(current)
    d.update(devicemk_rebound_from=str(p), devicemk_rebound_from_sha256=sha(p.read_bytes()),
             devicemk_only_change='Bluetooth profile property block (snapshot35)', devicemk_rebinding_scope=__doc__)
    (O/name).write_text(json.dumps(d, indent=2)+'\n')
(O/'report.json').write_text(json.dumps({'passed': True, 'inserted_block': inserted}, indent=2)+'\n')
print('PASS rebound device.mk-bound proofs; only the Bluetooth profile block was inserted')
