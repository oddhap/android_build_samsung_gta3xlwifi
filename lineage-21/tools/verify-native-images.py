#!/usr/bin/env python3
"""Validate completed build artifacts offline; never communicates with a device."""
import argparse
import hashlib
import gzip
import json
import struct
import zipfile
from pathlib import Path

root = Path('/srv/android')
parser = argparse.ArgumentParser()
parser.add_argument('--build-exit', type=Path, default=root / 'logs/lineage21-rom-build-final.exit')
parser.add_argument('--report', type=Path, default=root / 'artifacts/lineage-21/native-image-check.json')
parser.add_argument('--expected-kernel-sha256', default='9827c8ac986f7497428ac27e9bc309ac8b62ee08fbb414e6d0c81653537ea4a2',
                    help='SHA-256 of the independently reviewed source-built kernel')
args = parser.parse_args()
out = root / 'src/lineage-21.0/out/target/product/gta3xlwifi'
packaged = out / 'obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files/IMAGES'
exit_file = args.build_exit
if not exit_file.exists() or exit_file.read_text().strip() != '0':
    raise SystemExit('Full LineageOS 21 ROM build has not completed successfully')

limits = {
    'boot.img': 33554432, 'recovery.img': 47185920,
    'system.img': 3196059648, 'vendor.img': 343932928,
    'product.img': 327155712, 'dtbo.img': 8388608,
}
report = {'device': 'SM-T510', 'hardware_tested': False, 'images': {}}

def ramdisk_file(data, wanted):
    """Read one file from the gzip/newc ramdisk without executing its content."""
    unpacked = gzip.decompress(data)
    offset = 0
    while offset + 110 <= len(unpacked):
        header = unpacked[offset:offset + 110]
        if header[:6] not in (b'070701', b'070702'):
            raise SystemExit('Recovery ramdisk: unexpected CPIO format')
        size = int(header[54:62], 16)
        name_size = int(header[94:102], 16)
        name_start = offset + 110
        name = unpacked[name_start:name_start + name_size].rstrip(b'\0').decode()
        file_start = (name_start + name_size + 3) & ~3
        file_end = file_start + size
        if file_end > len(unpacked):
            raise SystemExit('Recovery ramdisk: truncated CPIO member')
        if name.removeprefix('./') == wanted:
            return unpacked[file_start:file_end]
        if name == 'TRAILER!!!':
            break
        offset = (file_end + 3) & ~3
    raise SystemExit(f'Recovery ramdisk: missing {wanted}')

for name, maximum in limits.items():
    # bacon creates system/product images inside target-files, not at OUT root.
    # Inspect the actual packaged images consistently, including boot/recovery.
    path = packaged / name
    if not path.is_file():
        raise SystemExit(f'Missing built image: {name}')
    data = path.read_bytes()
    sparse = len(data) >= 28 and struct.unpack_from('<I', data)[0] == 0xed26ff3a
    expanded_size = struct.unpack_from('<I', data, 12)[0] * struct.unpack_from('<I', data, 16)[0] if sparse else len(data)
    if expanded_size > maximum:
        raise SystemExit(f'{name}: expanded image exceeds physical partition size')
    item = {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'file_bytes': len(data),
            'expanded_bytes': expanded_size, 'partition_bytes': maximum}
    if name in ('boot.img', 'recovery.img'):
        if data[:8] != b'ANDROID!':
            raise SystemExit(f'{name}: unexpected boot image magic')
        fields = struct.unpack_from('<10I', data, 8)
        kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, _, _, tags_addr, page_size, version, _ = fields
        # CWA1 loads initrd at 0x89000000 and DTB at 0x8a000000.
        if ramdisk_size > 16777216:
            raise SystemExit(f'{name}: ramdisk overlaps bootloader DTB load region')
        item['ramdisk_bytes'] = ramdisk_size
        item['ramdisk_limit_bytes'] = 16777216
        expected_ramdisk_addr = 0x11000000 if ramdisk_size else 0
        if (kernel_addr, ramdisk_addr, tags_addr, page_size, version) != (0x10008000, expected_ramdisk_addr, 0x10000100, 2048, 1):
            raise SystemExit(f'{name}: boot header differs from reviewed SM-T510 layout')
        expected_board = b'SRPSA25A005KU' if name == 'boot.img' else b'SRPSA25A005RU'
        if data[48:64].rstrip(b'\0') != expected_board:
            raise SystemExit(f'{name}: unexpected board field')
        if not data.endswith(b'SEANDROIDENFORCE'):
            raise SystemExit(f'{name}: Samsung trailer missing')
        if name == 'boot.img' and ramdisk_size:
            raise SystemExit('boot.img: legacy system-as-root must not carry a boot ramdisk')
        if name == 'recovery.img' and not ramdisk_size:
            raise SystemExit('recovery.img: recovery ramdisk missing')
        if name == 'recovery.img':
            ramdisk_offset = page_size + ((kernel_size + page_size - 1) // page_size) * page_size
            usb_init = ramdisk_file(data[ramdisk_offset:ramdisk_offset + ramdisk_size],
                                   'init.recovery.exynos7904.rc')
            if b'on init\n    setprop sys.usb.configfs 1' not in usb_init:
                raise SystemExit('Recovery ramdisk: SM-T510 configfs USB setup missing')
            item['recovery_usb_configfs_selected'] = True
            recovery_fstab = ramdisk_file(data[ramdisk_offset:ramdisk_offset + ramdisk_size],
                                         'system/etc/recovery.fstab').decode()
            if not any(line.split()[:3] ==
                       ['/dev/block/platform/13500000.dwmmc0/by-name/misc', '/misc', 'emmc']
                       for line in recovery_fstab.splitlines()):
                raise SystemExit('Lineage recovery fstab: Android misc entry missing')
            item['standard_recovery_misc_fstab_verified'] = True
            dtbo_size, dtbo_offset, header_size = struct.unpack_from('<IQI', data, 1632)
            if header_size != 1648 or not dtbo_size or dtbo_offset % page_size:
                raise SystemExit('recovery.img: invalid embedded recovery DTBO layout')
            recovery_dtbo = data[dtbo_offset:dtbo_offset + dtbo_size]
            if hashlib.sha256(recovery_dtbo).hexdigest() != 'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b':
                raise SystemExit('recovery.img: embedded DTBO differs from reviewed container')
            item['embedded_dtbo_sha256'] = hashlib.sha256(recovery_dtbo).hexdigest()
        actual_kernel = hashlib.sha256(data[page_size:page_size + kernel_size]).hexdigest()
        if actual_kernel != args.expected_kernel_sha256:
            raise SystemExit(f'{name}: kernel differs from verified source-built artifact')
        item['kernel_sha256'] = actual_kernel
        item['header_version'] = version
    report['images'][name] = item

if report['images']['vendor.img']['sha256'] != '4cc684231b4a1c355169cea61b4ea5196401bc5f68c7f74a32c1ec290abc0006':
    raise SystemExit('Packaged vendor image differs from verified stock image')
if report['images']['dtbo.img']['sha256'] != 'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b':
    raise SystemExit('Packaged DTBO differs from the reviewed source-built container')

packages = sorted(out.glob('lineage-21.0-*-gta3xlwifi.zip'),
                  key=lambda p: (p.stat().st_mtime_ns, p.name))
if not packages:
    raise SystemExit('No device-specific LineageOS ZIP produced')
package = packages[-1]
with zipfile.ZipFile(package) as archive:
    failed_member = archive.testzip()
    if failed_member:
        raise SystemExit(f'ROM ZIP failed CRC verification: {failed_member}')
    metadata = archive.read('META-INF/com/android/metadata').decode()
    if 'pre-device=gta3xlwifi' not in metadata.splitlines():
        raise SystemExit('OTA metadata does not target gta3xlwifi')
report['rom_zip'] = str(package)
report['rom_zip_sha256'] = hashlib.sha256(package.read_bytes()).hexdigest()
report['ota_metadata'] = metadata
report['stability_claim'] = False
destination = args.report
destination.write_text(json.dumps(report, indent=2) + '\n')
print(f'Offline image and ZIP checks passed; report: {destination}')
print('Hardware behavior and stability have not been tested.')
