#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the installed system-server JNI contains the gated legacy power bridge."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

top, archive, geometry, host, output = map(Path, sys.argv[1:])

def digest(path):
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()

proof = json.loads(host.read_text())
image = json.loads(geometry.read_text())
assert proof['passed'] and image['artifact_checks_passed']
assert digest(archive) == image['archive_sha256']
for name, sha in proof['source_sha256'].items():
    assert digest(top/name) == sha
kernel = top/'device/samsung/gta3xlwifi/prebuilt/Image'
assert digest(kernel) == proof['kernel_sha256']
relative = 'system/lib64/libandroid_servers.so'
with zipfile.ZipFile(archive) as z, tempfile.TemporaryDirectory() as d:
    entry = 'SYSTEM/lib64/libandroid_servers.so'
    raw = z.read(entry)
    artifact = top/'out/target/product/gta3xlwifi'/relative
    assert raw == artifact.read_bytes()
    assert b'/sys/class/sec/tsp/double_tap_to_wake\x00' in raw
    assert b'/sys/class/sec/tsp/input_enabled\x00' in raw
    stripped = Path(d)/'libandroid_servers.so'
    stripped.write_bytes(raw)
    header = subprocess.check_output(['readelf','-h',stripped], text=True)
    assert 'AArch64' in header
    syms = subprocess.check_output(['readelf','--dyn-syms','--wide',stripped],text=True)
    native = ['_ZN10gta3xlwifi9powerModeEib', '_ZN10gta3xlwifi9initPowerEv',
              '_ZN10gta3xlwifi16interactionBoostEi']
    # The final library can hide or inline local static-library symbols.
    # Audit the unstripped link input as well as the actual installed ELF.
    bare = top/('out/soong/.intermediates/frameworks/base/services/libandroid_servers/'
                'android_arm64_armv8-a_shared/unstripped/libandroid_servers.so')
    assert bare.is_file()
    full = subprocess.check_output(['readelf','--syms','--wide',bare],text=True)
    assert all(any(name in line and ' UND ' not in line
                   for line in (full+'\n'+syms).splitlines()) for name in native)
    installed_id = subprocess.check_output(['readelf','-n',stripped],text=True).split('Build ID: ')[1].split()[0]
    symbol_id = subprocess.check_output(['readelf','-n',bare],text=True).split('Build ID: ')[1].split()[0]
    assert installed_id == symbol_id
output.write_text(json.dumps({
    'passed':True, 'archive_sha256':image['archive_sha256'],
    'installed_library_sha256':hashlib.sha256(raw).hexdigest(), 'elf_build_id': installed_id,
    'touch_host_proof_sha256':digest(host), 'kernel_sha256':digest(kernel),
    'physical_double_tap_wake_tested':False,
},indent=2)+'\n')
