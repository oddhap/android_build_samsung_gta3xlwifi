#!/usr/bin/env python3
"""Create unsigned AVB metadata for unlocked-device development testing only.

This script writes files on the build VM. It never flashes a device.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

root = Path('/srv/android')
avbtool = root / 'src/lineage-19.1/external/avb/avbtool.py'
destination = root / 'artifacts/test-boot'
destination.mkdir(parents=True, exist_ok=True)
image = destination / 'vbmeta-disabled.img'
command = [sys.executable, str(avbtool), 'make_vbmeta_image',
           '--algorithm', 'NONE', '--flags', '3', '--padding_size', '4096',
           '--output', str(image)]
subprocess.run(command, check=True)
data = image.read_bytes()
if data[:4] != b'AVB0' or len(data) != 4096:
    raise SystemExit('Unexpected AVB image layout')
flags = struct.unpack_from('>I', data, 120)[0]
algorithm = struct.unpack_from('>I', data, 28)[0]
if flags != 3 or algorithm != 0:
    raise SystemExit('Expected unsigned metadata with both disabled flags')
inspection = subprocess.check_output(
    [sys.executable, str(avbtool), 'info_image', '--image', str(image)], text=True)
(destination / 'vbmeta-disabled-info.txt').write_text(inspection)
report = {
    'image': str(image), 'sha256': hashlib.sha256(data).hexdigest(),
    'bytes': len(data), 'flags': flags, 'algorithm': 'NONE',
    'requires_unlocked_bootloader': True, 'hardware_tested': False,
    'verified_boot_disabled_for_development': True,
    'selinux_enforcement_changed': False,
    'command': command,
    'stock_vbmeta_preserved_at': '/srv/android/vendor-stock/images/vbmeta.img',
}
(destination / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
print(inspection)
print('Prepared for unlocked-device testing; no device was flashed.')
