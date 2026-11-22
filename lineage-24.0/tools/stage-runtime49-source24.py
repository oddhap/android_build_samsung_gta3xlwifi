#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed snapshot49 change on top of snapshot48.

source: the LineageOS Updater "Recent changes" button opens
        https://download.lineageos.org/gta3xlwifi/changes (string menu_changelog_url),
        which does not exist for this unofficial device. Add a static device overlay
        (DEVICE_PACKAGE_OVERLAYS, device.mk) for packages/apps/Updater that points the
        button at this device's GitHub releases, where every OTA release carries its
        changelog. Resource-only; no code, policy, vendor or kernel change.
"""
import hashlib
import json
from pathlib import Path
import subprocess

root = Path('/srv/android')
src = root/'src/lineage-24.0-arm64'
art = root/'artifacts/lineage-24.0-arm64'
port = root/'ports/lineage-24.0-arm64/lineage-24.0'
base = port/'snapshots'
project = 'device/samsung/gta3xlwifi'
inside = 'overlay/packages/apps/Updater/app/src/main/res/values/strings.xml'
URL = 'https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases'
CONTENT = f'''<?xml version="1.0" encoding="utf-8"?>
<!--
     SPDX-License-Identifier: Apache-2.0
     Unofficial device: download.lineageos.org has no changelog page for gta3xlwifi.
     Every OTA release on GitHub carries its changelog.
-->
<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
    <string name="menu_changelog_url" translatable="false">{URL}</string>
</resources>
'''


def read(path):
    return json.loads(path.read_text())


work = art/'runtime49-source-selection-20261122-01'
work.mkdir()
before = base/'port-20261122-48'
after = base/'port-20261122-49'
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert read(work/'source-before.json')['passed']
assert not after.exists()
device = src/project
upstream = (src/'packages/apps/Updater/app/src/main/res/values/strings.xml').read_text()
assert upstream.count('<string name="menu_changelog_url" translatable="false">https://download.lineageos.org/') == 1
assert (device/'device.mk').read_text().count('DEVICE_PACKAGE_OVERLAYS += $(LOCAL_PATH)/overlay\n') == 1
target = device/inside
assert not target.exists() and not (device/'overlay/packages/apps').exists()
(work/'edits.json').write_text(json.dumps({str(target): {'before_sha256': None,
    'after_sha256': hashlib.sha256(CONTENT.encode()).hexdigest()}}, indent=2)+'\n')
projects = [r['project'] for r in read(before/'source-lock.json')]
try:
    target.parent.mkdir(parents=True)
    target.write_text(CONTENT)
    subprocess.run(['git', '-C', device, 'add', '--intent-to-add', '--', inside], check=True)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    subprocess.run(['git', '-C', device, 'rm', '--cached', '--quiet', '--ignore-unmatch', '--', inside])
    if target.exists():
        target.unlink()
    for d in [target.parent, *target.parent.parents]:
        if d == device or not d.exists() or any(d.iterdir()):
            break
        d.rmdir()
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
print('PASS staged snapshot49:', after)
