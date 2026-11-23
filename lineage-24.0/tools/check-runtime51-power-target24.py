#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged system_server power backend to the snapshot51 retry change.

Usage: check-runtime51-power-target24.py TOP ARCHIVE GEOMETRY EDITS HOST_TESTS OUTPUT

Background: the bounded touch/launch CPU-GPU boost (device power/, linked into
libandroid_servers.so) disabled itself for the life of system_server on the first
failed control write; on build 50 it was found dead before a reboot, reason lost.
Snapshot51 suspends instead (releases the requests), logs the reason to the main and
system buffers, and reopens the controls after a 1 s .. 60 s backoff (RetryBackoff.h).

Requires: every edited/added source equals its staged after-hash; the three power
host tests (retry, window, touch-wake) ran with return code 0 from this build;
SYSTEM/lib64/libandroid_servers.so is arm64 ELF and carries the new suspend/recover
strings and the unchanged ready string, and no longer carries the old permanent
"disabling boost" string. Package check only; the runtime proof is on the device.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile

top, archive, geometry, edits, host_tests, output = map(Path, sys.argv[1:])
assert not output.exists()
g = json.loads(geometry.read_text())
assert g['artifact_checks_passed']
h = hashlib.sha256()
with archive.open('rb') as f:
    for block in iter(lambda: f.read(1 << 20), b''):
        h.update(block)
assert h.hexdigest() == g['archive_sha256'], 'Archive differs from the checked geometry report'
e = json.loads(edits.read_text())
power = top/'device/samsung/gta3xlwifi/power'
assert sorted(e) == sorted(str(power/n) for n in ['Power.cpp', 'Android.bp', 'RetryBackoff.h', 'RetryBackoffTest.cpp']), sorted(e)
for path, meta in e.items():
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == meta['after_sha256'], path+' is not the staged text'
t = json.loads(host_tests.read_text())
assert t['passed'] and set(t['tests']) == {'gta3xlwifi-power-retry-test', 'gta3xlwifi-power-window-test', 'gta3xlwifi-touch-wake-test'}
assert all(v['returncode'] == 0 for v in t['tests'].values())
with zipfile.ZipFile(archive) as z:
    lib = z.read('SYSTEM/lib64/libandroid_servers.so')
assert lib[:4] == b'\x7fELF' and lib[4] == 2 and struct.unpack_from('<H', lib, 18)[0] == 183
for needle in [b'Power boost suspended: %s %s failed errno=%d (%s)', b'Power boost recovered (%s) after',
               b'Bounded CPU/GPU boost ready: touch=400ms launch<=2000ms', b'/dev/gta3xlwifi_cluster0_min',
               b'/sys/devices/platform/11500000.mali/gta3xlwifi_min_lock']:
    assert lib.count(needle) >= 1, needle  # LOG_BOTH uses each format twice; pooling is not guaranteed
assert b'disabling boost' not in lib and b'Power boost disabled: cannot open controls' not in lib
output.write_text(json.dumps({'passed': True, 'host_tests_passed': True,
                              'libandroid_servers_sha256': hashlib.sha256(lib).hexdigest(),
                              'sources': {Path(p).name: m['after_sha256'] for p, m in e.items()},
                              'runtime_tested': False}, indent=2)+'\n')
print('PASS power-boost retry backend packaged:', output)
