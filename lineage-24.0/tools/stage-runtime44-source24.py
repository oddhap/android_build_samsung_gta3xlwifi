#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot44: OTA updates through the built-in LineageOS Updater (parent: snapshot43).

Exactly three reviewed source edits in device/samsung/gta3xlwifi:
- device.mk: lineage.updater.uri points the Updater at the JSON index on the
  ota branch of oddhap/android_build_samsung_gta3xlwifi
  (raw.githubusercontent.com: HTTPS, no redirect; the Updater refuses both).
- releasetools.py: run LineageOS backuptool (addon.d backup/restore) so GApps
  addon.d packages survive an OTA. Both stages run with the vendor and the
  unused physical product block devices set read-only (addon.d v3 would mount
  vendor rw). The backup stage runs only after both existing pre-write guards;
  vendor must be unmounted again (and released) before any image write, and the
  existing vendor-unmounted guard is re-run. The restore stage runs after all
  image writes and before the final read-only recovery recheck; if write
  protection is unavailable it is skipped (installation already complete).
- recovery-header-sync/recovery_header_sync.cpp: recognize the owner-approved
  TWRP 33875693... (fstab without /product, ABGR colour; identity de91185c...
  over 40271888 bytes with OS/SPL bytes 44..47 zeroed). All previous identities
  are kept.
No SELinux, vendor, kernel, prebuilt or other change."""
import hashlib, json, subprocess
from pathlib import Path
src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261121-43', port/'snapshots/port-20261121-44'
work = art/'runtime44-source-selection-20261121-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
D = src/'device/samsung/gta3xlwifi'
# Non-ro property values are limited to PROP_VALUE_MAX = 91 bytes (attempt a: 108).
URI = 'https://raw.githubusercontent.com/oddhap/android_build_samsung_gta3xlwifi/ota/{device}.json'
assert len(URI.encode()) <= 91
edits = {}
def edit(path, pairs):
    o = path.read_text(); u = o
    for a, b in pairs:
        assert u.count(a) == 1, (path, a)
        u = u.replace(a, b)
    edits[path] = (o, u)

edit(D/'device.mk', [(
    'PRODUCT_SYSTEM_PROPERTIES += debug.hwui.use_partial_updates=false\n',
    'PRODUCT_SYSTEM_PROPERTIES += debug.hwui.use_partial_updates=false\n'
    '\n'
    '# OTA index for the built-in LineageOS Updater (HTTPS without redirects).\n'
    '# Published by integration/lineage-24.0/tools/publish-ota-release24.py.\n'
    'PRODUCT_SYSTEM_PROPERTIES += \\\n'
    '    lineage.updater.uri=' + URI + '\n')])

ADDON_GUARD = (
    "#!/sbin/sh\n"
    "# Keep vendor and the unused physical product partition read-only while\n"
    "# addon.d scripts run; release only when neither is mounted.\n"
    "set -- \"$1\" /dev/block/platform/13500000.dwmmc0/by-name/vendor /dev/block/platform/13500000.dwmmc0/by-name/product\n"
    "[ -b \"$2\" ] && [ -b \"$3\" ] || exit 2\n"
    "case \"$1\" in\n"
    "protect)\n"
    "    blockdev --setro \"$2\" && blockdev --setro \"$3\" || exit 1\n"
    "    [ \"$(blockdev --getro \"$2\")\" = 1 ] && [ \"$(blockdev --getro \"$3\")\" = 1 ] || exit 1 ;;\n"
    "release)\n"
    "    [ -r /proc/mounts ] || exit 2\n"
    "    while read source mountpoint rest; do\n"
    "        case \"$mountpoint\" in /vendor|/vendor/*|/product|/product/*) exit 1 ;; esac\n"
    "    done < /proc/mounts\n"
    "    blockdev --setrw \"$2\" && blockdev --setrw \"$3\" || exit 1\n"
    "    [ \"$(blockdev --getro \"$2\")\" = 0 ] && [ \"$(blockdev --getro \"$3\")\" = 0 ] || exit 1 ;;\n"
    "*) exit 2 ;;\n"
    "esac\n"
    "exit 0\n")

edit(D/'releasetools.py', [
    ('_BIN = "gta3xlwifi_recovery_header_sync"\n',
     '_ADDON_GUARD = ' + repr(ADDON_GUARD.encode()) + '\n'
     '_SYSTEM_DEVICE = "/dev/block/platform/13500000.dwmmc0/by-name/system"\n'
     '_BACKUPTOOL = \'run_program("/tmp/install/bin/backuptool.sh", "%s", "\' + _SYSTEM_DEVICE + \'", "ext4");\'\n'
     '\n'
     '_BIN = "gta3xlwifi_recovery_header_sync"\n'),
    ("    info.script.AppendExtra('assert(run_program(\"/sbin/sh\", \"/tmp/vendor-unmounted-check.sh\") == \"0\" || '\n"
     "                            'abort(\"Vendor is mounted or its state cannot be verified. Stop recovery crypto services and unmount vendor.\"));')\n"
     "\n\ndef _end(info):\n"
     "    _, word = _target(info)\n",
     "    info.script.AppendExtra('assert(run_program(\"/sbin/sh\", \"/tmp/vendor-unmounted-check.sh\") == \"0\" || '\n"
     "                            'abort(\"Vendor is mounted or its state cannot be verified. Stop recovery crypto services and unmount vendor.\"));')\n"
     "    # LineageOS addon.d backup (GApps survival) after both guards, with vendor and\n"
     "    # the unused product partition read-only; vendor must be unmounted again\n"
     "    # before any image write.\n"
     "    common.ZipWriteStr(info.output_zip, \"addon-vendor-guard.sh\", _ADDON_GUARD)\n"
     "    info.script.AppendExtra('package_extract_file(\"addon-vendor-guard.sh\", \"/tmp/addon-vendor-guard.sh\");')\n"
     "    info.script.AppendExtra('package_extract_dir(\"install\", \"/tmp/install\");')\n"
     "    info.script.AppendExtra('set_metadata_recursive(\"/tmp/install\", \"uid\", 0, \"gid\", 0, \"dmode\", 0755, \"fmode\", 0644);')\n"
     "    info.script.AppendExtra('set_metadata_recursive(\"/tmp/install/bin\", \"uid\", 0, \"gid\", 0, \"dmode\", 0755, \"fmode\", 0755);')\n"
     "    info.script.AppendExtra('assert(run_program(\"/sbin/sh\", \"/tmp/addon-vendor-guard.sh\", \"protect\") == \"0\" || '\n"
     "                            'abort(\"Cannot write-protect vendor/product for the addon.d backup. Installation stopped before image writes.\"));')\n"
     "    info.script.AppendExtra(_BACKUPTOOL % \"backup\")\n"
     "    info.script.AppendExtra('assert(run_program(\"/sbin/sh\", \"/tmp/addon-vendor-guard.sh\", \"release\") == \"0\" || '\n"
     "                            'abort(\"Vendor or product is still mounted after the addon.d backup. Installation stopped before image writes.\"));')\n"
     "    info.script.AppendExtra('assert(run_program(\"/sbin/sh\", \"/tmp/vendor-unmounted-check.sh\") == \"0\" || '\n"
     "                            'abort(\"Vendor is mounted after the addon.d backup. Installation stopped before image writes.\"));')\n"
     "\n\ndef _end(info):\n"
     "    _, word = _target(info)\n"
     "    # addon.d restore after all image writes; skipped if write protection is\n"
     "    # unavailable (images are already complete).\n"
     "    info.script.AppendExtra('if run_program(\"/sbin/sh\", \"/tmp/addon-vendor-guard.sh\", \"protect\") == \"0\" then')\n"
     "    info.script.AppendExtra(_BACKUPTOOL % \"restore\")\n"
     "    info.script.AppendExtra('run_program(\"/sbin/sh\", \"/tmp/addon-vendor-guard.sh\", \"release\");')\n"
     "    info.script.AppendExtra('else ui_print(\"Vendor/product write protection unavailable: addon.d restore skipped.\"); endif;')\n"),
])
compile(edits[D/'releasetools.py'][1], 'releasetools.py', 'exec')

edit(D/'recovery-header-sync/recovery_header_sync.cpp', [(
    '    {40271888, "01e34bd1051135bf4b7e8a024bf28f70499f742cdc842d8434ee2037cf59c8e3"},\n',
    '    {40271888, "01e34bd1051135bf4b7e8a024bf28f70499f742cdc842d8434ee2037cf59c8e3"},\n'
    '    // Owner-approved 2026-11-21: TWRP fstab without /product and ABGR colour\n'
    '    // (recovery 33875693...); kernel, DTBO and header word unchanged.\n'
    '    {40271888, "de91185c3dbbed822612c5478780aa0bd4cb1c77c0b20c42e29cd0301b3b65bb"},\n')])

originals = work/'originals'
originals.mkdir()
for path, (o, u) in edits.items():
    (originals/(path.name + '.original')).write_text(o)
(work/'addon-vendor-guard.sh').write_text(ADDON_GUARD)
(work/'edits.json').write_text(json.dumps({str(p): {'before_sha256': hashlib.sha256(o.encode()).hexdigest(),
    'after_sha256': hashlib.sha256(u.encode()).hexdigest()} for p, (o, u) in edits.items()}, indent=2)+'\n')
(work/'updater.json').write_text(json.dumps({'lineage.updater.uri': URI,
    'addon_vendor_guard_sha256': hashlib.sha256(ADDON_GUARD.encode()).hexdigest(),
    'new_recovery_identity': {'bytes': 40271888, 'identity': 'de91185c3dbbed822612c5478780aa0bd4cb1c77c0b20c42e29cd0301b3b65bb',
                              'recovery_sha256': '33875693066aeb5e9f27bc2d469c3052b438552395cb476ed0d8340348765f05'}}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    for path, (o, u) in edits.items():
        path.write_text(u)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for path, (o, u) in edits.items():
        path.write_text(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime43-inputs-20261121-02/report.json'
r = json.loads(p.read_text())
assert r['passed'] and r['source_snapshot'] == str(before)
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p), runtime_prebuilts_changed=False)
out = art/'runtime44-inputs-20261121-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot44 Updater URI + addon.d backuptool + TWRP identity de91185c:', after)
