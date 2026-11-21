#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot40: fold /product into /system so the official MindTheGapps 17 ZIP fits.

The physical product partition (327155712 bytes, ~292 MiB usable ext4) is
smaller than even the reduced MindTheGapps-17.0.0-arm64 payload (~307 MiB incl.
its 10 MiB buffer after its own low-resource removals; ~730 MiB complete). The
installer supports devices whose /product is a symlink inside system and then
installs into system (3196059648 bytes, >1 GiB free). Snapshot40 therefore:

- BoardConfig.mk: no product image (drop BOARD_PRODUCTIMAGE_PARTITION_SIZE and
  BOARD_PRODUCTIMAGE_FILE_SYSTEM_TYPE); TARGET_COPY_OUT_PRODUCT := system/product,
  the same layout system_ext already uses on this device.
- device.mk: PRODUCT_BUILD_PRODUCT_IMAGE := false (was true; Kati rejects true
  without a product filesystem type; attempt a failed there and was reverted).
- rootdir/etc/fstab.exynos7904: the first-stage /product mount line is replaced by
  a comment. The physical partition is left untouched (no repartition, no format,
  no erase); the OTA simply stops writing it.

No policy, vendor, kernel, boot image, recovery or TWRP change. The device.mk
make-module override for product modules becomes a no-op.
"""
import hashlib, json, subprocess
from pathlib import Path

src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261121-39', port/'snapshots/port-20261121-40'
work = art/'runtime40-product-in-system-selection-20261121-01'
work.mkdir()
sha = lambda b: hashlib.sha256(b).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
dev = src/'device/samsung/gta3xlwifi'
board, fstab, devmk = dev/'BoardConfig.mk', dev/'rootdir/etc/fstab.exynos7904', dev/'device.mk'

FSTAB_OLD = b'/dev/block/platform/13500000.dwmmc0/by-name/product /product ext4 ro wait,first_stage_mount\n'
FSTAB_NEW = (b'# /product is part of system (/product -> /system/product) so the official GApps\n'
             b'# installer fits; the physical product partition is no longer mounted or written.\n')
DEVMK_EDITS = [
    (b'PRODUCT_BUILD_PRODUCT_IMAGE := true\n',
     b'# Product is part of system (see BoardConfig.mk); no separate product image.\n'
     b'PRODUCT_BUILD_PRODUCT_IMAGE := false\n'),
]
BOARD_EDITS = [
    (b'BOARD_PRODUCTIMAGE_PARTITION_SIZE := 327155712\n', b''),
    (b'BOARD_PRODUCTIMAGE_FILE_SYSTEM_TYPE := ext4\n', b''),
    (b'TARGET_COPY_OUT_PRODUCT := product\n',
     b'# No product image: the physical product partition is too small for the\n'
     b'# official MindTheGapps 17 ZIP. Product content lives in system (like\n'
     b'# system_ext); the partition itself is left untouched and unused.\n'
     b'TARGET_COPY_OUT_PRODUCT := system/product\n'),
]

edits = {}
o = board.read_bytes(); u = o
for old, new in BOARD_EDITS:
    assert u.count(old) == 1, old
    u = u.replace(old, new)
assert b'PRODUCTIMAGE' not in u
edits[board] = (o, u)
o = devmk.read_bytes(); u = o
for old, new in DEVMK_EDITS:
    assert u.count(old) == 1, old
    u = u.replace(old, new)
edits[devmk] = (o, u)
o = fstab.read_bytes()
assert o.count(FSTAB_OLD) == 1 and b'/vendor ext4 ro wait,first_stage_mount' in o and b'fileencryption=ice' in o
edits[fstab] = (o, o.replace(FSTAB_OLD, FSTAB_NEW))

originals = work/'originals'
originals.mkdir()
for f, (o, u) in edits.items():
    (originals/(f.name + '.original')).write_bytes(o)
(work/'edits.json').write_text(json.dumps({str(f): {'before_sha256': sha(o), 'after_sha256': sha(u)}
                                           for f, (o, u) in edits.items()}, indent=2)+'\n')
(work/'replacements.json').write_text(json.dumps({
    'BoardConfig.mk': [[a.decode(), b.decode()] for a, b in BOARD_EDITS],
    'device.mk': [[a.decode(), b.decode()] for a, b in DEVMK_EDITS],
    'fstab.exynos7904': [[FSTAB_OLD.decode(), FSTAB_NEW.decode()]]}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    for f, (o, u) in edits.items():
        f.write_bytes(u)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for f, (o, u) in edits.items():
        f.write_bytes(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime39-inputs-20261121-01/report.json'
r = json.loads(p.read_text())
assert r['passed']
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p.read_bytes()), runtime_prebuilts_changed=False)
out = art/'runtime40-inputs-20261121-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot40 product-in-system layout:', after)
