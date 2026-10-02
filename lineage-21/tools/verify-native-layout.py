#!/usr/bin/env python3
"""Verify the actual ext4 system root used by Samsung's kernel-only boot."""
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

root = Path('/srv/android')
top = root / 'src/lineage-21.0'
out = top / 'out/target/product/gta3xlwifi'
report_dir = root / 'artifacts/lineage-21'
images = json.loads((report_dir / 'native-image-check.json').read_text())
image = Path(images['images']['system.img']['path'])
debugfs = top / 'out/host/linux-x86/bin/debugfs_static'
checks = {'hardware_tested': False, 'system_image_sha256': images['images']['system.img']['sha256']}

with tempfile.TemporaryDirectory(prefix='gta3xlwifi-system-layout-', dir=report_dir) as directory:
    raw = Path(directory) / 'system.raw.img'
    with image.open('rb') as stream:
        sparse = struct.unpack('<I', stream.read(4))[0] == 0xed26ff3a
    if sparse:
        subprocess.run([str(top / 'out/host/linux-x86/bin/simg2img'), str(image), str(raw)], check=True)
    else:
        raw = image

    def read_file(name):
        result = subprocess.run([str(debugfs), '-R', f'cat {name}', str(raw)], capture_output=True, check=True)
        if b'File not found' in result.stderr or b'not a regular file' in result.stderr:
            raise SystemExit(f'Missing system-root file: {name}')
        return result.stdout

    result = subprocess.run([str(debugfs), '-R', 'stat /init', str(raw)], capture_output=True, check=True)
    if b'Fast link dest: "/system/bin/init"' not in result.stdout:
        raise SystemExit('System image /init does not point to /system/bin/init')
    init = read_file('/system/bin/init')
    if init[:5] != b'\x7fELF\x01' or init[18:20] != b'\x28\x00':
        raise SystemExit('System-root init is missing or is not ARM32 ELF')
    checks['init_sha256'] = hashlib.sha256(init).hexdigest()
    device = top / 'device/samsung/gta3xlwifi'
    for member, source in (
        ('/fstab.exynos7904', device / 'rootdir/etc/fstab.exynos7904'),
        ('/init.exynos7904.rc', device / 'rootdir/init.exynos7904.rc'),
        ('/ueventd.exynos7904.rc', device / 'rootdir/ueventd.exynos7904.rc'),
        ('/system/system_ext/etc/init/init.gta3xlwifi.power.rc', device / 'rootdir/init.gta3xlwifi.power.rc'),
    ):
        data = read_file(member)
        if data != source.read_bytes():
            raise SystemExit(f'System-root file differs from its reviewed source: {member}')
        checks[member] = hashlib.sha256(data).hexdigest()
    props = read_file('/system/build.prop')
    if b'ro.build.version.release=14\n' not in props:
        raise SystemExit('Physical system image lacks Android 14 properties')
    if b'ro.gta3xlwifi.legacy_networking=true\n' not in props:
        raise SystemExit('Physical system image lacks the networking backend selector')

checks['passed'] = True
(report_dir / 'native-layout-check.json').write_text(json.dumps(checks, indent=2) + '\n')
print(json.dumps(checks, indent=2))
