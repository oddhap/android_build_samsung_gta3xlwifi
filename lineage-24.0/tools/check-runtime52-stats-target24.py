#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged service-connectivity.jar to the snapshot52 unknown-ifindex change.

Usage: check-runtime52-stats-target24.py TOP ARCHIVE GEOMETRY EDITS HOST_TEST OUTPUT

Background (issue #5): Gta3xlwifiStatsConsumer threw "Missing real interface history"
for stats rows whose ifindex has no interface name, crash-looping system_server on
Wi-Fi. Snapshot52 skips such rows and logs as A17 BpfNetworkStats.cpp does.

Requires: both edited sources equal their staged after-hashes; the host test passed on
exactly those after-hashes; SYSTEM/apex/com.android.tethering.capex -> original_apex ->
javalib/service-connectivity.jar (extracted with the built deapexer) carries the new
log text and no longer the three old throw texts. Package check only.
"""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

top, archive, geometry, edits, host_test, output = map(Path, sys.argv[1:])
assert not output.exists()
g = json.loads(geometry.read_text())
assert g['artifact_checks_passed']
h = hashlib.sha256()
with archive.open('rb') as f:
    for block in iter(lambda: f.read(1 << 20), b''):
        h.update(block)
assert h.hexdigest() == g['archive_sha256'], 'Archive differs from the checked geometry report'
e = json.loads(edits.read_text())
server = top/'packages/modules/Connectivity/service/src/com/android/server'
assert sorted(e) == sorted(str(server/n) for n in ['Gta3xlwifiStatsConsumer.java', 'Gta3xlwifiTrafficStats.java'])
for path, meta in e.items():
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == meta['after_sha256'], path+' is not the staged text'
t = json.loads(host_test.read_text())
assert t['passed'] and t['after_sha256'] == {Path(p).name: m['after_sha256'] for p, m in e.items()}
assert t['phases']['fixed']['returncode'] == 0 and t['phases']['regression']['returncode'] != 0
with zipfile.ZipFile(archive) as z:
    capex = z.read('SYSTEM/apex/com.android.tethering.capex')
with zipfile.ZipFile(io.BytesIO(capex)) as c:
    apex = c.read('original_apex')
bin_ = top/'out/host/linux-x86/bin'
with tempfile.TemporaryDirectory() as d:
    (Path(d)/'t.apex').write_bytes(apex)
    subprocess.run([str(bin_/'deapexer'), '--debugfs_path', str(bin_/'debugfs_static'), '--fsckerofs_path',
                    str(bin_/'fsck.erofs'), 'extract', str(Path(d)/'t.apex'), str(Path(d)/'x')],
                   check=True, capture_output=True)
    jar = (Path(d)/'x/javalib/service-connectivity.jar').read_bytes()
with zipfile.ZipFile(io.BytesIO(jar)) as j:
    dex = b''.join(j.read(n) for n in j.namelist() if n.endswith('.dex'))
assert dex.count(b'Gta3xlwifiStatsConsumer') >= 1
for needle in [b'Unknown name for ifindex ', b' bytes of traffic', b'Gta3xlwifiStats']:
    assert needle in dex, needle
for gone in [b'Missing real interface history', b'Missing interface summary history',
             b'Incomplete interface-name history']:
    assert gone not in dex, gone
output.write_text(json.dumps({'passed': True, 'host_test_passed': True,
                              'tethering_capex_sha256': hashlib.sha256(capex).hexdigest(),
                              'service_connectivity_jar_sha256': hashlib.sha256(jar).hexdigest(),
                              'sources': {Path(p).name: m['after_sha256'] for p, m in e.items()},
                              'runtime_tested': False}, indent=2)+'\n')
print('PASS stats unknown-ifindex skip packaged:', output)
