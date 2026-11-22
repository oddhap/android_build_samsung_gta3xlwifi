#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind host proofs that hash-bind device.mk to the snapshot44 file.

Snapshot44 only inserts the lineage.updater.uri block (four lines plus a blank
line) in device.mk. Require that each proof's device.mk digest is the
snapshot43 file (= the snapshot40 rebind), and that the current file is exactly
that original with only the recorded snapshot44 replacement applied. All other
bound sources must still match. Proof results are carried over unchanged;
nothing is re-tested.
"""
import hashlib, json, sys
from pathlib import Path

A = Path('/srv/android/artifacts/lineage-24.0-arm64')
T = Path('/srv/android/src/lineage-24.0-arm64')
O = A/sys.argv[1]
O.mkdir()
rel = 'device/samsung/gta3xlwifi/device.mk'
sha = lambda b: hashlib.sha256(b).hexdigest()
work = A/'runtime44-source-selection-20261121-01'
original = (work/'originals/device.mk.original').read_bytes()
current = (T/rel).read_bytes()
e = json.loads((work/'edits.json').read_text())[str(T/rel)]
assert sha(original) == e['before_sha256'] and sha(current) == e['after_sha256']
uri = json.loads((work/'updater.json').read_text())['lineage.updater.uri']
anchor = b'PRODUCT_SYSTEM_PROPERTIES += debug.hwui.use_partial_updates=false\n'
block = (b'\n# OTA index for the built-in LineageOS Updater (HTTPS without redirects).\n'
         b'# Published by integration/lineage-24.0/tools/publish-ota-release24.py.\n'
         b'PRODUCT_SYSTEM_PROPERTIES += \\\n    lineage.updater.uri=' + uri.encode() + b'\n')
assert original.count(anchor) == 1 and original.replace(anchor, anchor + block) == current
assert b'lineage.updater.uri' not in original
proofs = ['ui-host-proof.json', 'bpf-kernel-actual-host-report.json']
for name in proofs:
    p = A/'runtime40-devicemk-rebind-20261121-01'/name
    d = json.loads(p.read_text())
    assert d['passed'] and d['source_sha256'][rel] == sha(original), name
    for other, h in d['source_sha256'].items():
        assert other == rel or sha((T/other).read_bytes()) == h, other
    d['source_sha256'][rel] = sha(current)
    d.update(devicemk44_rebound_from=str(p), devicemk44_rebound_from_sha256=sha(p.read_bytes()),
             devicemk44_only_change='lineage.updater.uri block (snapshot44)',
             devicemk44_rebinding_scope=__doc__)
    (O/name).write_text(json.dumps(d, indent=2)+'\n')
(O/'report.json').write_text(json.dumps({'passed': True, 'devicemk_before_sha256': sha(original),
    'devicemk_after_sha256': sha(current), 'lineage_updater_uri': uri}, indent=2)+'\n')
print('PASS rebound device.mk-bound proofs; only the Updater URI block changed')
