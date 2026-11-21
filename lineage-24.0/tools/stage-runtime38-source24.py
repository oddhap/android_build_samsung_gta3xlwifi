#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot38: decouple the boot image header patch level from the system one.

Samsung's TEE keymaster binds the FBE key blobs to the OS patch level that the
bootloader reads from the booted image header (offset 44). The installed TWRP
header carries 0x220001ab (Android 17 / 2026-11, owner-approved one-byte edit),
and TWRP can only use the key blobs while both headers agree. AOSP builds the
boot header from PLATFORM_SECURITY_PATCH, so every new ASB month would raise the
boot header (one-way for the key blobs) and need another TWRP header edit.

1. BoardConfig.mk: BOOT_SECURITY_PATCH := 2026-11-01 (the AOSP board variable for
   the boot image level; with AVB disabled it only feeds the unused AVB
   property and Soong's unused boot image generator).
2. mkbootimg.mk: the custom Samsung boot rule replaces
   INTERNAL_MKBOOTIMG_VERSION_ARGS (os_patch_level = PLATFORM_SECURITY_PATCH,
   build/make/core/Makefile) with the same os_version and BOOT_SECURITY_PATCH.
   Recovery packaging is unchanged (the installer never writes recovery).
3. releasetools.py: the preflight word comes from the fixed boot level, the boot
   header must equal it, and the system level must not be older. Kernel digest,
   Android 17 release, ARM32 helper, vendor and recovery --preflight guards stay.
ro.build.version.security_patch keeps following the platform; the prebuilt
vendor image (ro.vendor.build.security_patch) is untouched.
Policy, vendor, kernel unchanged from build 37.
"""
import hashlib, json, subprocess
from pathlib import Path

src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261120-37', port/'snapshots/port-20261121-38'
work = art/'runtime38-bootspl-selection-20261121-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
dev = src/'device/samsung/gta3xlwifi'
edits = {}

# 1. BoardConfig.mk: fixed boot image patch level.
f = dev/'BoardConfig.mk'
o = f.read_text()
assert sha(f) == 'ece7f0815d05ebdffb2833251ba439cd2a64323685c689b4f764c822203ff29b'
anchor = ('BOARD_MKBOOTIMG_ARGS := --header_version 1 --kernel_offset 0x00008000 --ramdisk_offset 0x01000000 '
          '--tags_offset 0x00000100 --board SRPSA25A005KU\n')
assert o.count(anchor) == 1 and 'SECURITY_PATCH' not in o
BOARD_BLOCK = ('# Fixed boot image header OS patch level (Samsung TEE keymaster input). The\n'
               '# installed TWRP header carries the same word (0x220001ab), so monthly\n'
               '# security updates must not raise it; ro.build.version.security_patch keeps\n'
               '# following the platform. Raising it is one-way for the FBE key blobs and\n'
               '# needs a reviewed TWRP header change. Used by mkbootimg.mk/releasetools.py.\n'
               'BOOT_SECURITY_PATCH := 2026-11-01\n')
u = o.replace(anchor, anchor + BOARD_BLOCK)
edits[f] = (o, u)

# 2. mkbootimg.mk: boot header os_patch_level from BOOT_SECURITY_PATCH.
f = dev/'mkbootimg.mk'
o = f.read_text()
assert sha(f) == '64a037c5e8e3ffe180a1a004d9a6f5844a0f68922c21c69fc82ef18c3ac493e8'
old_cmd = ('\t$(MKBOOTIMG) --kernel $(call bootimage-to-kernel,$@) $(GTA3XLWIFI_BOOTIMAGE_ARGS) '
           '$(INTERNAL_MKBOOTIMG_VERSION_ARGS) $(BOARD_MKBOOTIMG_ARGS) --output $@\n')
assert o.count(old_cmd) == 1 and o.count('$(INTERNAL_MKBOOTIMG_VERSION_ARGS)') == 1
anchor = 'GTA3XLWIFI_BOOTIMAGE_ARGS = $(filter-out --ramdisk $(INSTALLED_RAMDISK_TARGET),$(INTERNAL_BOOTIMAGE_ARGS))\n'
assert o.count(anchor) == 1
MK_BLOCK = ('\n# The boot header patch level is a Keymaster input shared with TWRP: use the\n'
            '# fixed board level instead of PLATFORM_SECURITY_PATCH (see BoardConfig.mk).\n'
            'ifeq ($(words $(subst -, ,$(BOOT_SECURITY_PATCH))),3)\n'
            'else\n'
            '$(error BOOT_SECURITY_PATCH must be set to the fixed YYYY-MM-DD boot level)\n'
            'endif\n'
            'GTA3XLWIFI_BOOTIMAGE_VERSION_ARGS = --os_version $(PLATFORM_VERSION_LAST_STABLE) '
            '--os_patch_level $(BOOT_SECURITY_PATCH)\n')
new_cmd = old_cmd.replace('$(INTERNAL_MKBOOTIMG_VERSION_ARGS)', '$(GTA3XLWIFI_BOOTIMAGE_VERSION_ARGS)')
u = o.replace(anchor, anchor + MK_BLOCK).replace(old_cmd, new_cmd)
edits[f] = (o, u)

# 3. releasetools.py: guard against the fixed boot level.
f = dev/'releasetools.py'
o = f.read_text()
assert sha(f) == '9c07c5835364dc4ac4fddbc80366f0002ed6724f1e9f3efa8b81c44e2931f77b'
anchor = '_STATUS = "/tmp/gta3xlwifi-recovery-header.status"\n'
RT_CONST = ('\n# Fixed boot image patch level (BoardConfig.mk BOOT_SECURITY_PATCH). Samsung\'s\n'
            '# keymaster binds key blobs to the boot header level, and the installed TWRP\n'
            '# header carries the same word; the system level may advance independently.\n'
            '_BOOT_SECURITY_PATCH = "2026-11-01"\n')
old_body = (
    '    release = props["ro.build.version.release"]\n'
    '    patch = props["ro.build.version.security_patch"]\n'
    '    if release not in ("17", "17.0", "17.0.0") or not re.fullmatch(r"20\\d\\d-(0[1-9]|1[0-2])-\\d\\d", patch):\n'
    '        raise ValueError("This test package requires Android 17 target metadata")\n'
    '    year, month, _ = map(int, patch.split("-"))\n'
    '    if not 2020 <= year <= 2127:\n'
    '        raise ValueError("Patch year is outside the supported boot-header range")\n'
    '    expected = (17 << 25) | ((year - 2000) << 4) | month\n'
    '    if struct.unpack_from("<I", boot, 44)[0] != expected:\n'
    '        raise ValueError("ROM properties and boot-header Keymaster inputs differ")\n')
new_body = (
    '    release = props["ro.build.version.release"]\n'
    '    patch = props["ro.build.version.security_patch"]\n'
    '    level = r"20\\d\\d-(0[1-9]|1[0-2])-\\d\\d"\n'
    '    if (release not in ("17", "17.0", "17.0.0") or not re.fullmatch(level, patch) or\n'
    '            not re.fullmatch(level, _BOOT_SECURITY_PATCH)):\n'
    '        raise ValueError("This test package requires Android 17 target metadata")\n'
    '    if patch[:7] < _BOOT_SECURITY_PATCH[:7]:\n'
    '        raise ValueError("System patch level is older than the fixed boot patch level")\n'
    '    year, month, _ = map(int, _BOOT_SECURITY_PATCH.split("-"))\n'
    '    if not 2020 <= year <= 2127:\n'
    '        raise ValueError("Patch year is outside the supported boot-header range")\n'
    '    expected = (17 << 25) | ((year - 2000) << 4) | month\n'
    '    if struct.unpack_from("<I", boot, 44)[0] != expected:\n'
    '        raise ValueError("Boot header differs from the fixed boot-image Keymaster patch level")\n')
assert o.count(anchor) == 1 and o.count(old_body) == 1 and '_BOOT_SECURITY_PATCH' not in o
u = o.replace(anchor, anchor + RT_CONST).replace(old_body, new_body)
edits[f] = (o, u)

originals = work/'originals'
originals.mkdir()
for f, (o, _) in edits.items():
    (originals/(f.name + '.original')).write_text(o)
(work/'edits.json').write_text(json.dumps({str(k): {'before_sha256': hashlib.sha256(v[0].encode()).hexdigest(),
    'after_sha256': hashlib.sha256(v[1].encode()).hexdigest()} for k, v in edits.items()}, indent=2)+'\n')
(work/'inserted.json').write_text(json.dumps({'BoardConfig.mk': BOARD_BLOCK, 'mkbootimg.mk': MK_BLOCK,
    'releasetools.py_constant': RT_CONST, 'releasetools.py_old_body': old_body,
    'releasetools.py_new_body': new_body}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    for f, (_, u) in edits.items():
        f.write_text(u)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for f, (o, _) in edits.items():
        f.write_text(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime37-inputs-20261120-01/report.json'
r = json.loads(p.read_text())
assert r['passed']
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p), runtime_prebuilts_changed=False)
out = art/'runtime38-inputs-20261121-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot38 fixed boot image patch level:', after)
