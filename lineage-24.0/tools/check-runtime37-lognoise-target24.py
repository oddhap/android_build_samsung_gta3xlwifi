#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged snapshot37 log-noise corrections to the actual target files.

Checks: the four edited sources equal the reviewed selection (edits.json); the
packaged iptables, init, 32/64-bit libcutils and services.jar equal the fresh
build outputs and differ from build 36 (so the change is really packaged), and
the retained diagnostics (iptables extension warning, libcutils readlink error)
are still present for genuinely unsupported cases. Packaging only; the log
effect requires the physical test."""
import hashlib, json, sys, zipfile
from pathlib import Path
top, archive, geometry, output = map(Path, sys.argv[1:5])
assert not output.exists()
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
def sha(f):
    h = hashlib.sha256()
    with f.open('rb') as s:
        for b in iter(lambda: s.read(1048576), b''): h.update(b)
    return h.hexdigest()
g = json.loads(geometry.read_text()); assert g['artifact_checks_passed'] and sha(archive) == g['archive_sha256']
sel = json.loads((A/'runtime37-lognoise-selection-20261120-01/edits.json').read_text())
assert len(sel) == 4
for name, rec in sel.items():
    assert sha(Path(name)) == rec['after_sha256'], name
entries = {'SYSTEM/bin/iptables': 'system/bin/iptables', 'SYSTEM/bin/init': 'system/bin/init',
           'SYSTEM/lib/libcutils.so': 'system/lib/libcutils.so', 'SYSTEM/lib64/libcutils.so': 'system/lib64/libcutils.so',
           'SYSTEM/framework/services.jar': 'system/framework/services.jar'}
out = top/'out/target/product/gta3xlwifi'
packaged = {}
with zipfile.ZipFile(archive) as z, zipfile.ZipFile(A/'runtime36-ota-build-20261120-01/target-files.zip') as old:
    for entry, built in entries.items():
        data = z.read(entry)
        assert data == (out/built).read_bytes(), entry
        assert data != old.read(entry), f'{entry} unchanged from build 36'
        packaged[entry] = hashlib.sha256(data).hexdigest()
    assert b'is not supported, missing kernel module?' in z.read('SYSTEM/bin/iptables')
    assert b'readlink(%s) failed: %m' in z.read('SYSTEM/lib64/libcutils.so')
output.write_text(json.dumps(dict(passed=True, scope=__doc__, archive_sha256=g['archive_sha256'],
    source_sha256={k: v['after_sha256'] for k, v in sel.items()}, packaged_sha256=packaged,
    readback_verification_changed=False, sepolicy_changed=False, physical_log_tested=False), indent=2)+'\n')
print('PASS packaged snapshot37 log-noise corrections')
