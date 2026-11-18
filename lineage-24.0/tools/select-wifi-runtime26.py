#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select the reviewed strict vendor cache and preserve the previous image."""
import fcntl
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

root = Path('/srv/android')
top = root / 'src/lineage-24.0-arm64'
art = root / 'artifacts/lineage-24.0-arm64'
port = root / 'ports/lineage-24.0-arm64/lineage-24.0'
output = art / 'runtime26-inputs-20261118-01'
snapshot = port / 'snapshots/port-20261118-26'

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else digest_stream(stream)

def digest_stream(stream):
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        h.update(block)
    return h.hexdigest()

def read(path):
    return json.loads(path.read_text())

with (root / 'logs/lineage-24.0-arm64/build.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    old = art / 'runtime25-inputs-20261118-01/report.json'
    result = read(old)
    assert result['passed'] and result['original_rollback_copies_verified']
    previous = result['after'].copy()
    strict = art / 'ion-ui-policy-strict-20261117-01/strict/report.json'
    vendor = art / 'wifi-supplicant-vendor-20261118-02/report.json'
    binding = art / 'wifi-ota-binding-host-20261118-01/report.json'
    access = art / 'ion-ui-built-access-20261118-01/report.json'
    assertions = strict.parent.parent / 'assertions.json'
    policy = read(strict)
    composition = read(vendor)
    assert policy['passed_strict'] and not policy['explicit_input_overrides']
    assert composition['passed'] and composition['strict_report_sha256'] == digest(strict)
    assert read(assertions)['passed'] and read(access)['passed']
    assert read(access)['policy_sha256'] == digest(strict.parent / 'strict.policy')
    assert read(binding)['passed'] and read(binding)['vendor_report_sha256'] == digest(vendor)
    for name, expected in read(binding)['source_sha256'].items():
        assert digest(top / name) == expected
    for item in policy['inputs']:
        assert digest(Path(item['path'])) == item['sha256']
    prebuilts = top / 'device/samsung/gta3xlwifi/prebuilt'
    for name, expected in previous.items():
        assert digest(prebuilts / name) == expected
    for name, expected in result['before'].items():
        assert digest(art / 'runtime-input-selection-20261116-01/original-prebuilts' / name) == expected
    image = vendor.parent / 'vendor.img'
    expected = composition['vendor_sparse_sha256']
    assert digest(image) == expected
    output.mkdir()
    subprocess.run(['python3', str(port / 'tools/audit-port.py'), str(top), str(snapshot),
                    str(output / 'source-audit.json')], check=True)
    shutil.copyfile(prebuilts / 'vendor.img', output / 'previous-vendor.img')
    assert digest(output / 'previous-vendor.img') == previous['vendor.img']
    temporary = prebuilts / 'vendor.img.ion-ui.tmp'
    assert not temporary.exists()
    shutil.copyfile(image, temporary)
    assert digest(temporary) == expected
    temporary.replace(prebuilts / 'vendor.img')
    result['after']['vendor.img'] = expected
    result.update(source_snapshot=str(snapshot), previous_selected_prebuilts=previous,
                  inherited_runtime_selection_sha256=digest(old),
                  runtime_prebuilts_changed=True, flash_ready=False,
                  compiled_CIL_inputs_expected_unchanged=policy['inputs'],
                  proofs_sha256={str(p): digest(p) for p in (strict, vendor, binding, access, assertions)})
    (output / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
