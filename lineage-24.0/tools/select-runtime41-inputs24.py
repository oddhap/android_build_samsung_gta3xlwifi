#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select the cache that was linked with the exact snapshot41 platform policy."""
import fcntl
import hashlib
import json
from pathlib import Path
import shutil

root=Path('/srv/android')
top=root/'src/lineage-24.0-arm64'
art=root/'artifacts/lineage-24.0-arm64'
current=root/'ports/lineage-24.0-arm64/lineage-24.0/snapshots/port-20261121-41'
previous=art/'runtime40-inputs-20261121-01/report.json'
strict=art/'gmsion-policy-strict-20261121-01/strict/report.json'
vendor=art/'gmsion-vendor-20261121-01/report.json'
access=art/'gmsion-built-access-20261121-01/report.json'
delta=art/'runtime41-ota-selection-20261121-01/vendor-delta.json'
output=art/'runtime41-inputs-20261121-01'
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
    assert r['source_snapshot']==str(current.with_name('port-20261121-40'))
    assert load(current/'port-audit.json')['passed']
    p=load(strict)
    v=load(vendor)
    assert p['passed_strict'] and not p['explicit_input_overrides']
    assert p['results'][0]['neverallow_checks_enabled'] and '-N' not in p['results'][0]['command']
    assert v['passed'] and v['strict_report_sha256']==sha(strict)
    assert load(delta)['passed'] and load(delta)['candidate_report_sha256']==sha(vendor)
    assert load(access)['passed'] and load(access)['policy_sha256']==v['strict_policy_sha256']
    assert all(sha(Path(item['path']))==item['sha256'] for item in p['inputs'])
    for name,digest in r['after'].items():
        assert sha(prebuilts/name)==digest
    for name,digest in r['before'].items():
        assert sha(art/'runtime-input-selection-20261116-01/original-prebuilts'/name)==digest
    destination=prebuilts/'vendor.img'
    candidate=vendor.parent/'vendor.img'
    expected=v['vendor_sparse_sha256']
    assert sha(candidate)==expected
    assert (top/'device/samsung/gta3xlwifi/releasetools.py').read_text().count(expected)==1
    output.mkdir()
    backup=output/'previous-vendor.img'
    shutil.copyfile(destination,backup)
    assert sha(backup)==r['after']['vendor.img']
    temporary=prebuilts/'vendor.img.runtime41.tmp'
    assert not temporary.exists()
    shutil.copyfile(candidate,temporary)
    assert sha(temporary)==expected
    r['previous_selected_prebuilts']=r['after'].copy()
    r['after']['vendor.img']=expected
    r.update(source_snapshot=str(current),runtime_prebuilts_changed=True,
             inherited_runtime_selection_sha256=sha(previous),flash_ready=False,
             compiled_CIL_inputs_expected_unchanged=p['inputs'],proofs_sha256={
             str(f):sha(f) for f in (strict,vendor,access,delta,strict.parent.parent/'assertions.json')})
    temporary.replace(destination)
    (output/'report.json').write_text(json.dumps(r,indent=2)+'\n')
