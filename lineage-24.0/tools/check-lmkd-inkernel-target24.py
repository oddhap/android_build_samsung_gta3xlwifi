#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the reviewed LMKD implementation in the packaged compiled artifact."""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

top, archive, geometry, output = map(Path, sys.argv[1:])
artifacts = Path('/srv/android/artifacts/lineage-24.0-arm64')
proof = artifacts / 'lmkd-inkernel-composition-20261118-01/host-report.json'
host = json.loads(proof.read_text())
assert host['passed']
for path, expected in host['source_sha256'].items():
    assert hashlib.sha256((top / path).read_bytes()).hexdigest() == expected
g = json.loads(geometry.read_text())
assert g['artifact_checks_passed']
with zipfile.ZipFile(archive) as z, zipfile.ZipFile(
        artifacts / 'runtime22-ota-build-20261117-01/target-files.zip') as previous:
    binary = z.read('SYSTEM/bin/lmkd')
    assert binary == (top / 'out/target/product/gta3xlwifi/system/bin/lmkd').read_bytes()
    assert binary != previous.read('SYSTEM/bin/lmkd')
    assert z.read('SYSTEM/etc/init/lmkd.rc') == previous.read('SYSTEM/etc/init/lmkd.rc')
assert not output.exists()
output.write_text(json.dumps({
    'passed': True,
    'archive_sha256': g['archive_sha256'],
    'host_proof_sha256': hashlib.sha256(proof.read_bytes()).hexdigest(),
    'lmkd_sha256': hashlib.sha256(binary).hexdigest(),
    'hardware_validated': False,
}, indent=2) + '\n')
