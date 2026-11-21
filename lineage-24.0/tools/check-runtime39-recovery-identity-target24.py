#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged snapshot39 recovery preflight helper to the reviewed source.

Checks: the edited source equals the selection; the host test passed on that
source; the packaged ARM32 static helper equals the fresh build output, differs
from build 38, contains all four known identities (three previous + the
owner-approved TWRP 01e34bd1...) and no --apply mode."""
import hashlib, json, struct, sys, zipfile
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
sel = json.loads((A/'runtime39-recovery-identity-selection-20261121-01/edits.json').read_text())
(name, rec), = sel.items()
assert sha(Path(name)) == rec['after_sha256']
host = json.loads((A/'runtime39-recovery-identity-host-20261121-01/report.json').read_text())
assert host['passed'] and host['source_sha256'] == rec['after_sha256']
ids = [b'0c641ba8f29bd9a4063cf9e8670dfc84124bc926f7bead643977685827306cc6',
       b'd8878895ec55959e9f3697c1ee3e8a983e304067a2cde26baa51d00fe664b751',
       b'5eb6d0f8fbb75f08d7156d3de1118fc429eff44543fd61e6a7c1b8c99dc21239',
       b'01e34bd1051135bf4b7e8a024bf28f70499f742cdc842d8434ee2037cf59c8e3']
entry = 'SYSTEM/bin/gta3xlwifi_recovery_header_sync'
with zipfile.ZipFile(archive) as z, zipfile.ZipFile(A/'runtime38-ota-build-20261121-01/target-files.zip') as old:
    helper = z.read(entry)
    assert helper == (top/'out/target/product/gta3xlwifi/system/bin/gta3xlwifi_recovery_header_sync').read_bytes()
    previous = old.read(entry)
    assert helper != previous, 'helper unchanged from build 38'
    assert helper[:5] == b'\x7fELF\x01' and struct.unpack_from('<H', helper, 18)[0] == 40
    assert all(i in helper for i in ids) and b'--preflight' in helper and b'--apply' not in helper
    assert b'--test-image' not in helper, 'host test mode must not be in the device binary'
output.write_text(json.dumps(dict(passed=True, scope=__doc__, archive_sha256=g['archive_sha256'],
    source_sha256=rec['after_sha256'], packaged_helper_sha256=hashlib.sha256(helper).hexdigest(),
    previous_helper_sha256=hashlib.sha256(previous).hexdigest(),
    host_test_report_sha256=sha(A/'runtime39-recovery-identity-host-20261121-01/report.json'),
    known_identities=[i.decode() for i in ids], recovery_written=False), indent=2)+'\n')
print('PASS packaged recovery preflight helper recognizes the owner-approved TWRP')
