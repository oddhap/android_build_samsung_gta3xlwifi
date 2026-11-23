#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select the sdfat-exfat kernel Image (gate-split kernel + sdfat "exfat" alias) for snapshot53.

Policy, vendor and dtbo are unchanged from the build 52 selection;
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
snapshot = root/'ports/lineage-24.0-arm64/lineage-24.0/snapshots/port-20261123-52'
previous = art/'runtime52-inputs-20261123-01/report.json'
kernel = art/'kernel-sdfat-exfat-build-20261123-01'
output = art/'runtime53-inputs-20261123-01'
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
    assert k['passed'] and k['host_sdfat_exfat_cases'] == 10 and k['kernel_config_identical_to_active']
    assert k['complete_source_protected_baseline_Android_audits'] and k['actual_Image_all_modules_and_Gator_built']
    image = kernel/'Image'
    expected = sha(image)
    assert expected == k['Image_sha256'] and k['previous_Image_sha256'] == r['after']['Image']
    assert load(kernel/'host/report.json')['passed']
    lock_report = load(kernel/'overlay-lock.json')
    assert sorted(lock_report['baseline']['original_sha256']) == ['fs/sdfat/sdfat.c']
    for name, digest in r['after'].items():
        assert sha(prebuilts/name) == digest, name
    output.mkdir()
    backup = output/'previous-Image'
    shutil.copyfile(prebuilts/'Image', backup)
    assert sha(backup) == r['after']['Image']
    temporary = prebuilts/'Image.runtime53.tmp'
    assert not temporary.exists()
    shutil.copyfile(image, temporary)
    assert sha(temporary) == expected
    r['previous_selected_prebuilts'] = r['after'].copy()
    r['after']['Image'] = expected
    r.update(source_snapshot=str(snapshot), runtime_prebuilts_changed=True,
             inherited_runtime_selection_sha256=sha(previous), flash_ready=False,
             kernel_build_report_sha256=sha(kernel/'report.json'),
             kernel_change='sdfat also registers as "exfat" (fs/sdfat/sdfat.c only; issue 4)')
    r.setdefault('proofs_sha256', {})[str(kernel/'report.json')] = sha(kernel/'report.json')
    temporary.replace(prebuilts/'Image')
    (output/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS selected sdfat-exfat kernel Image', expected)
