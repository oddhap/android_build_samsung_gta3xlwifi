#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind UI regression evidence and product EGL setting to actual target files."""
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zipfile

top, archive, geometry, host, output = map(Path, sys.argv[1:])
before = Path('/srv/android/artifacts/lineage-24.0-arm64/runtime26-ota-build-20261118-01/target-files.zip')

def sha(data):
    return hashlib.sha256(data).hexdigest()

expected = json.loads(geometry.read_text())
proof = json.loads(host.read_text())
assert expected['artifact_checks_passed'] and proof['passed']
digest = hashlib.sha256()
with archive.open('rb') as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
assert digest.hexdigest() == expected['archive_sha256']
for name, digest in proof['source_sha256'].items():
    assert sha((top/name).read_bytes()) == digest
with zipfile.ZipFile(archive) as current, zipfile.ZipFile(before) as previous:
    properties = current.read('SYSTEM/build.prop').decode().splitlines()
    property_name = 'debug.hwui.use_partial_updates='
    assert [p for p in properties if p.startswith(property_name)] == [property_name+'false']
    checks = {
        'framework.jar': (b'KeyButtonDrawable;', b'preferHardwareBitmap'),
        'services.jar': (b'DisplayDeviceConfig;', b'setSimpleMappingStrategyValues'),
    }
    jar_sha256 = {}
    for jar_name, markers in checks.items():
        entry = 'SYSTEM/framework/' + jar_name
        jar = current.read(entry)
        assert jar == (top/'out/target/product/gta3xlwifi/system/framework'/jar_name).read_bytes()
        assert jar != previous.read(entry)
        with zipfile.ZipFile(io.BytesIO(jar)) as nested:
            assert any(all(marker in dex for marker in markers)
                       for name in nested.namelist()
                       if re.fullmatch(r'classes(?:\d+)?\.dex', name)
                       for dex in [nested.read(name)])
        jar_sha256[jar_name] = sha(jar)
output.write_text(json.dumps({
    'passed': True, 'archive_sha256': expected['archive_sha256'],
    'ui_host_proof_sha256': sha(host.read_bytes()), 'jar_sha256': jar_sha256,
    'partial_updates_disabled_on_device': True, 'physical_ui_tested': False,
}, indent=2)+'\n')
