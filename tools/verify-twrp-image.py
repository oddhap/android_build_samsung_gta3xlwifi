#!/usr/bin/env python3
"""Check native TWRP output and create the Samsung-marked image; no USB access."""
import gzip
import lzma
import hashlib
import json
import struct
import subprocess
import re
from pathlib import Path

root = Path('/srv/android')
checkout = root / 'src/twrp-12.1'
source = checkout / 'out/target/product/gta3xlwifi/recovery.img'
destination = root / 'artifacts/twrp-sm-t510'
maximum = 47185920
kernel_sha = '445f0b44dd53f2bc464e95e2729307cc2cea1baf6f35db9b22327b0f7c352edd'
dtbo_sha = 'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b'
marker = b'SEANDROIDENFORCE'

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def cpio_members(data):
    if data.startswith(b'\x1f\x8b'):
        archive = gzip.decompress(data)
    elif data.startswith(b'\xfd7zXZ\x00'):
        archive = lzma.decompress(data)
    else:
        raise SystemExit('Unexpected recovery ramdisk compression')
    offset = 0
    result = {}
    while offset + 110 <= len(archive):
        header = archive[offset:offset + 110]
        require(header[:6] in (b'070701', b'070702'), 'Unexpected recovery CPIO format')
        size = int(header[54:62], 16)
        name_size = int(header[94:102], 16)
        name_start = offset + 110
        name = archive[name_start:name_start + name_size].rstrip(b'\0').decode()
        start = (name_start + name_size + 3) & ~3
        end = start + size
        require(end <= len(archive), 'Truncated recovery CPIO')
        if name == 'TRAILER!!!':
            return result
        result[name.removeprefix('./')] = archive[start:end]
        offset = (end + 3) & ~3
    raise SystemExit('Recovery CPIO lacks trailer')

require((root / 'logs/twrp-build.exit').read_text().strip() == '0', 'TWRP build did not pass')
data = source.read_bytes()
require(data[:8] == b'ANDROID!', 'Missing Android boot header')
fields = struct.unpack_from('<10I', data, 8)
kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, _, _, tags_addr, page_size, version, _ = fields
require(ramdisk_size <= 16777216, 'Ramdisk overlaps bootloader DTB load address')
require((kernel_addr, ramdisk_addr, tags_addr, page_size, version) ==
        (0x10008000, 0x11000000, 0x10000100, 2048, 1), 'Unexpected SM-T510 boot layout')
require(data[48:64].rstrip(b'\0') == b'SRPSA25A005RU', 'Wrong CWA1 recovery board field')
cmdline = (data[64:576].split(b'\0', 1)[0] + data[608:1632].split(b'\0', 1)[0]).decode()
require('androidboot.hardware=exynos7904' in cmdline, 'Wrong recovery hardware')
require('androidboot.selinux=enforcing' in cmdline and 'selinux=permissive' not in cmdline,
        'Global SELinux boot mode changed')
require(digest(data[page_size:page_size + kernel_size]) == kernel_sha, 'Unexpected kernel artifact')
ramdisk_offset = page_size + ((kernel_size + page_size - 1) // page_size) * page_size
members = cpio_members(data[ramdisk_offset:ramdisk_offset + ramdisk_size])
props = {}
for line in members['prop.default'].decode().splitlines():
    if line and not line.startswith('#') and '=' in line:
        key, value = line.split('=', 1)
        props[key] = value
require(props.get('ro.adb.secure') == '0', 'Recovery ADB still requires authorization')
require(props.get('ro.adb.secure.recovery') == '0', 'Missing recovery authentication property')
# Android init derives ro.product.model/device from partition-scoped properties.
# An image's prop.default can correctly omit the derived runtime properties.
for key, expected in [('model', 'SM-T510'), ('device', 'gta3xlwifi')]:
    values = [value for name, value in props.items()
              if name == f'ro.product.{key}' or
              (name.startswith('ro.product.') and name.endswith(f'.{key}'))]
    require(values and all(value == expected for value in values), f'Wrong recovery {key}')
usb_init = members['init.recovery.exynos7904.rc']
require(b'setprop sys.usb.configfs 1' in usb_init, 'Missing SM-T510 configfs selection')
require(b'mtp,adb' in usb_init and b'sys.usb.ffs.mtp.ready=1' in usb_init,
        'Missing MTP/ADB configfs support')
recovery = members['system/bin/recovery']
adbd = members['system/bin/adbd']
for name, binary in [('recovery', recovery), ('adbd', adbd)]:
    require(binary[:6] == b'\x7fELF\x01\x01' and struct.unpack_from('<H', binary, 18)[0] == 40,
            f'{name}: wrong userspace ABI')
require(b'3.7.1_12' in recovery, 'Recovery is not the expected TWRP version')
ramdisk_root = checkout / 'out/target/product/gta3xlwifi/recovery/root'
for library in ('libminuitwrp.so', 'libresetprop.so', 'libfscrypttwrp.so'):
    current_library = checkout / 'out/target/product/gta3xlwifi/system/lib' / library
    require(members.get(f'system/lib/{library}') == current_library.read_bytes(),
            f'Stale runtime library copied into recovery ramdisk: {library}')
libraries = {p.name: p for p in ramdisk_root.rglob('*.so') if p.is_file()}
pending = [ramdisk_root / f'system/bin/{name}' for name in ('init', 'recovery', 'adbd')]
visited = set()
while pending:
    binary_path = pending.pop().resolve()
    if binary_path in visited:
        continue
    visited.add(binary_path)
    packed_path = binary_path.relative_to(ramdisk_root.resolve()).as_posix()
    require(members.get(packed_path) == binary_path.read_bytes(),
            f'Runtime dependency absent or different in packed ramdisk: {packed_path}')
    dynamic = subprocess.run(['readelf', '-d', str(binary_path)],
                             check=True, capture_output=True, text=True).stdout
    for needed in re.findall(r'Shared library: \[(.*?)\]', dynamic):
        require(needed in libraries, f'Missing recovery runtime dependency: {needed}')
        pending.append(libraries[needed])
require(members.get('etc') in (b'/system/etc', b'system/etc'), 'Recovery /etc symlink overwritten')
require(b'/dev/block/platform/13500000.dwmmc0/by-name/userdata' in members['system/etc/twrp.fstab'],
        'Wrong recovery data partition')
require(b'fileencryption=ice' in members['system/etc/twrp.fstab'], 'FBE flag missing')
standard_fstab = members['system/etc/recovery.fstab'].decode()
misc_entries = [line.split() for line in standard_fstab.splitlines()
                if line.strip() and not line.lstrip().startswith('#')]
require(any(entry[:3] == ['/dev/block/platform/13500000.dwmmc0/by-name/misc',
                         '/misc', 'emmc'] for entry in misc_entries),
        'Android fs_mgr recovery fstab cannot find physical misc partition')
dtbo_size, dtbo_offset, header_size = struct.unpack_from('<IQI', data, 1632)
require(header_size == 1648 and dtbo_size > 0 and dtbo_offset % page_size == 0,
        'Bad embedded recovery DTBO layout')
require(digest(data[dtbo_offset:dtbo_offset + dtbo_size]) == dtbo_sha, 'Wrong embedded DTBO')

# Stock Samsung recovery carries this marker. It is not a cryptographic signature.
marked = data if data.endswith(marker) else data + marker
require(len(marked) <= maximum, 'TWRP exceeds actual RECOVERY PIT size')
destination.mkdir(parents=True, exist_ok=True)
image = destination / 'recovery-twrp-sm-t510.img'
image.write_bytes(marked)
report = {
    'device': 'SM-T510', 'version': '3.7.1_12', 'build_exit_code': 0,
    'image': str(image), 'sha256': digest(marked), 'file_bytes': len(marked),
    'partition_bytes': maximum, 'kernel_sha256': kernel_sha, 'dtbo_sha256': dtbo_sha,
    'boot_header_version': version, 'cmdline': cmdline,
    'ramdisk_bytes': ramdisk_size, 'ramdisk_limit_bytes': 16777216,
    'ramdisk_compression': 'xz',
    'adb_auth_required_in_recovery': False, 'usb_configfs': True,
    'fbe_enabled_in_device_config': True, 'samsung_fbe_runtime_tested': False,
    'upstream_twrp_permissive_recovery_domains': True,
    'hardware_tested': False, 'stability_claim': False,
    'original_unmarked_image_sha256': digest(data),
    'source_manifest_sha256': digest((root / 'artifacts/twrp-12.1-source-manifest.xml').read_bytes()),
    'recovery_elf_sha256': digest(recovery), 'adbd_elf_sha256': digest(adbd),
    'runtime_elf_dependencies_verified': len(visited),
    'graphics_library_sha256': digest(members['system/lib/libminuitwrp.so']),
    'graphics_library_matches_current_build': True,
    'fscrypt_library_sha256': digest(members['system/lib/libfscrypttwrp.so']),
}
(destination / 'image-check.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
