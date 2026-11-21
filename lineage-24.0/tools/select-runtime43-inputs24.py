#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select the gate-split -02 kernel Image (HOLD argument variant) for snapshot43.

Policy, vendor and dtbo are unchanged from the build 42 selection;
only prebuilt/Image changes, with a verified rollback copy.
"""
import fcntl
import hashlib
import json
from pathlib import Path
import shutil

root = Path('/srv/android')
top = root/'src/lineage-24.0-arm64'
art = root/'artifacts/lineage-24.0-arm64'
snapshot = root/'ports/lineage-24.0-arm64/lineage-24.0/snapshots/port-20261121-42'
previous = art/'runtime42-inputs-20261121-02/report.json'
kernel = art/'kernel-gate-split-build-20261121-02'
output = art/'runtime43-inputs-20261121-01'
prebuilts = top/'device/samsung/gta3xlwifi/prebuilt'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as s:
        for block in iter(lambda: s.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def load(path):
    return json.loads(path.read_text())


with (root/'logs/lineage-24.0-arm64/build.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    r = load(previous)
    assert r['passed'] and r['original_rollback_copies_verified']
    assert r['source_snapshot'] == str(snapshot)
    assert load(snapshot/'port-audit.json')['passed']
    k = load(kernel/'report.json')
    assert k['passed'] and k['host_gate_split_cases'] == 62 and k['kernel_config_identical_to_active']
    assert k['complete_source_protected_baseline_Android_audits'] and k['actual_Image_all_modules_and_Gator_built']
    image = kernel/'Image'
    expected = sha(image)
    assert expected == k['Image_sha256'] and k['previous_Image_sha256'] == r['after']['Image']
    assert load(kernel/'host/report.json')['passed']
    for name, digest in r['after'].items():
        assert sha(prebuilts/name) == digest, name
    output.mkdir()
    backup = output/'previous-Image'
    shutil.copyfile(prebuilts/'Image', backup)
    assert sha(backup) == r['after']['Image']
    temporary = prebuilts/'Image.runtime43.tmp'
    assert not temporary.exists()
    shutil.copyfile(image, temporary)
    assert sha(temporary) == expected
    r['previous_selected_prebuilts'] = r['after'].copy()
    r['after']['Image'] = expected
    r.update(source_snapshot=str(snapshot), runtime_prebuilts_changed=True,
             inherited_runtime_selection_sha256=sha(previous), flash_ready=False,
             kernel_build_report_sha256=sha(kernel/'report.json'),
             kernel_change='gate split -02: HOLD(HOLD_UPDATE_ARG) keeps packet gate open (ABI 2)')
    r.setdefault('proofs_sha256', {})[str(kernel/'report.json')] = sha(kernel/'report.json')
    temporary.replace(prebuilts/'Image')
    (output/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS selected gate-split kernel Image', expected)
