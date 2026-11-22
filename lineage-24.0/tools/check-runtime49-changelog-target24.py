#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged LineageOS Updater changelog URL to the snapshot49 overlay.

Usage: check-runtime49-changelog-target24.py TOP ARCHIVE GEOMETRY EDITS OUTPUT

Requires: the overlay file equals the staged after-hash; the packaged
SYSTEM/system_ext/priv-app/Updater/Updater.apk (dumped with the built aapt2)
has exactly one default value for string/menu_changelog_url, equal to the
device's GitHub releases URL, and no download.lineageos.org changelog value.
Package check only; the button itself is tested on the device.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

URL = 'https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases'
top, archive, geometry, edits, output = map(Path, sys.argv[1:])
assert not output.exists()
g = json.loads(geometry.read_text())
assert g['artifact_checks_passed']
h = hashlib.sha256()
with archive.open('rb') as f:
    for block in iter(lambda: f.read(1 << 20), b''):
        h.update(block)
assert h.hexdigest() == g['archive_sha256'], 'Archive differs from the checked geometry report'
e = json.loads(edits.read_text())
(overlay, meta), = e.items()
overlay = Path(overlay)
assert overlay == top/'device/samsung/gta3xlwifi/overlay/packages/apps/Updater/app/src/main/res/values/strings.xml'
assert hashlib.sha256(overlay.read_bytes()).hexdigest() == meta['after_sha256'], 'Overlay is not the staged text'
with tempfile.TemporaryDirectory(dir=output.parent) as scratch, zipfile.ZipFile(archive) as z:
    apk = Path(scratch)/'Updater.apk'
    apk.write_bytes(z.read('SYSTEM/system_ext/priv-app/Updater/Updater.apk'))
    apk_sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    dump = subprocess.run([str(top/'out/host/linux-x86/bin/aapt2'), 'dump', 'resources', str(apk)],
                          check=True, capture_output=True, text=True).stdout
lines = dump.splitlines()
idx = [i for i, l in enumerate(lines) if re.search(r'\bstring/menu_changelog_url$', l)]
assert len(idx) == 1, idx
values = []
for l in lines[idx[0]+1:]:
    m = re.match(r'\s+\(([^)]*)\) "(.*)"$', l)
    if not m:
        break
    values.append(m.groups())
assert values == [('', URL)], values
assert 'download.lineageos.org' not in ''.join(v for _, v in values)
output.write_text(json.dumps({'passed': True, 'updater_apk_sha256': apk_sha, 'menu_changelog_url': URL,
                              'overlay_sha256': meta['after_sha256'], 'runtime_tested': False}, indent=2)+'\n')
print('PASS Updater changelog URL packaged:', URL)
