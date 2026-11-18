#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the existing verified kernel and vendor inputs to the audited UI snapshot."""
import fcntl
import hashlib
import json
from pathlib import Path

root = Path('/srv/android')
art = root/'artifacts/lineage-24.0-arm64'
top = root/'src/lineage-24.0-arm64'
snapshots = root/'ports/lineage-24.0-arm64/lineage-24.0/snapshots'
snapshot = snapshots/'port-20261118-27'
report = art/'runtime26-inputs-20261118-01/report.json'
output = art/'runtime27-inputs-20261118-01'

def digest(path):
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()

with (root/'logs/lineage-24.0-arm64/build.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    parent = snapshots/'port-20261118-26'
    result = json.loads(report.read_text())
    assert result['passed'] and result['original_rollback_copies_verified']
    assert result['source_snapshot'] == str(parent)
    assert (snapshot/'port-manifest.xml').read_bytes() == (parent/'port-manifest.xml').read_bytes()
    parent_rows = {row['project']: row for row in json.loads((parent/'source-lock.json').read_text())}
    rows = {row['project']: row for row in json.loads((snapshot/'source-lock.json').read_text())}
    assert rows.keys() == parent_rows.keys()
    assert {p for p in rows if rows[p] != parent_rows[p]} == {
        'frameworks/base', 'device/samsung/gta3xlwifi'}
    audit = json.loads((snapshot/'port-audit.json').read_text())
    assert audit['passed'] and audit['manifest_sha256'] == digest(snapshot/'port-manifest.xml')
    for path, sha in result['proofs_sha256'].items():
        assert digest(Path(path)) == sha
    for item in result['compiled_CIL_inputs_expected_unchanged']:
        assert digest(Path(item['path'])) == item['sha256']
    for directory, entries in (
        (top/'device/samsung/gta3xlwifi/prebuilt', result['after']),
        (art/'runtime-input-selection-20261116-01/original-prebuilts', result['before']),
    ):
        assert {name: digest(directory/name) for name in entries} == entries
    result.update(source_snapshot=str(snapshot), runtime_prebuilts_changed=False,
                  inherited_runtime_selection_sha256=digest(report), flash_ready=False,
                  previous_selected_prebuilts=result['after'].copy())
    output.mkdir()
    (output/'report.json').write_text(json.dumps(result, indent=2) + '\n')
