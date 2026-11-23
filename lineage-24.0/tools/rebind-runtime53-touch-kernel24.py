#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind the touch/double-tap proof to the snapshot53 sdfat-exfat kernel Image.

The new kernel differs from the installed gate-split -02 kernel only in
fs/sdfat/sdfat.c (overlay lock + full tree audits; identical .config), so the touch
driver sources and config are byte-identical. Every userspace file bound by the
runtime51 proof must be unchanged. Physical double-tap evidence was obtained on the
previous kernel and is carried over, not re-tested. Nothing in the source tree is written.
"""
import hashlib, json, sys
from pathlib import Path

A = Path('/srv/android/artifacts/lineage-24.0-arm64')
top = Path('/srv/android/src/lineage-24.0-arm64')
O = A/sys.argv[1]
assert not O.exists()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
proof_path = A/'runtime51-touch-rebind-20261123-01/touch-host-proof.json'
proof = json.loads(proof_path.read_text())
assert proof['passed']
build = A/'kernel-sdfat-exfat-build-20261123-01'
k = json.loads((build/'report.json').read_text())
assert k['passed'] and k['kernel_config_identical_to_active']
assert proof['kernel_sha256'] == k['previous_Image_sha256']
assert sha(top/'device/samsung/gta3xlwifi/prebuilt/Image') == k['Image_sha256']
for name, digest in proof['source_sha256'].items():
    assert sha(top/name) == digest, name
lock = json.loads((build/'overlay-lock.json').read_text())
assert sorted(lock['baseline']['original_sha256']) == ['fs/sdfat/sdfat.c']
src = Path('/srv/android/ports/lineage-24.0-arm64/kernel-sdfat-exfat-20261123-01/src')
old = Path('/srv/android/ports/lineage-24.0-arm64/kernel-gate-split-20261121-02/src')
for rel in ['drivers/input/touchscreen', 'drivers/input/input.c']:
    a, b = old/rel, src/rel
    files = sorted(p.relative_to(a) for p in a.rglob('*') if p.is_file()) if a.is_dir() else [Path('')]
    for f in files:
        x, y = (a/f, b/f) if a.is_dir() else (a, b)
        assert sha(x) == sha(y), str(x)
out = dict(proof)
out.update(kernel_sha256=k['Image_sha256'], rebound_from=str(proof_path), rebound_from_sha256=sha(proof_path),
           kernel_rebinding={'previous_kernel_sha256': k['previous_Image_sha256'],
                             'kernel_build_report_sha256': sha(build/'report.json'),
                             'only_changed_kernel_files': ['fs/sdfat/sdfat.c'],
                             'touch_driver_sources_identical': True,
                             'physical_double_tap_retested_on_new_kernel': False},
           rebinding_scope=__doc__)
O.mkdir()
(O/'touch-host-proof.json').write_text(json.dumps(out, indent=2)+'\n')
(O/'report.json').write_text(json.dumps({'passed': True, 'kernel_sha256': k['Image_sha256']}, indent=2)+'\n')
print('PASS rebound touch proof to sdfat-exfat kernel; touch sources identical')
