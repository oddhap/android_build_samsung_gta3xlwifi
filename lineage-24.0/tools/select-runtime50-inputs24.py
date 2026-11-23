#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind the unchanged snapshot49 runtime inputs to snapshot50.

Snapshot50 adds only PRODUCT_ENABLE_UFFD_GC := false (product makefile); no policy,
vendor, kernel or DTBO input changes. The selected prebuilts and every strict
policy input must still be byte-identical; nothing in the source tree is written.
"""
import fcntl
import hashlib
import json
from pathlib import Path

root=Path('/srv/android')
top=root/'src/lineage-24.0-arm64'
art=root/'artifacts/lineage-24.0-arm64'
current=root/'ports/lineage-24.0-arm64/lineage-24.0/snapshots/port-20261122-50'
previous=art/'runtime49-inputs-20261122-01/report.json'
output=art/'runtime50-inputs-20261122-01'
prebuilts=top/'device/samsung/gta3xlwifi/prebuilt'

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as s:
        for block in iter(lambda:s.read(1024*1024),b''):
            h.update(block)
    return h.hexdigest()

def load(path):
    return json.loads(path.read_text())

with (root/'logs/lineage-24.0-arm64/build.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    r=load(previous)
    assert r['passed'] and r['original_rollback_copies_verified']
    assert r['source_snapshot']==str(current.with_name('port-20261122-49'))
    assert load(current/'port-audit.json')['passed']
    for f,digest in r['proofs_sha256'].items():
        assert sha(Path(f))==digest,f
    assert all(sha(Path(item['path']))==item['sha256'] for item in r['compiled_CIL_inputs_expected_unchanged'])
    for name,digest in r['after'].items():
        assert sha(prebuilts/name)==digest
    for name,digest in r['before'].items():
        assert sha(art/'runtime-input-selection-20261116-01/original-prebuilts'/name)==digest
    output.mkdir()
    r['previous_selected_prebuilts']=r['after'].copy()
    r.update(source_snapshot=str(current),runtime_prebuilts_changed=False,
             inherited_runtime_selection_sha256=sha(previous),flash_ready=False)
    (output/'report.json').write_text(json.dumps(r,indent=2)+'\n')
print('PASS runtime50 inputs:',output/'report.json')
