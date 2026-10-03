#!/usr/bin/env python3
"""Verify the actual ext4 system root used by Samsung's kernel-only boot."""
import hashlib
import json
import re
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
header = (root / 'src/kernel-gta3xlwifi/fs/ext4/ext4.h').read_text().replace('\\\n', ' ')
supported = {}
for kind in ('INCOMPAT', 'RO_COMPAT'):
    values = dict((name, int(value, 16)) for name, value in re.findall(
        rf'#define\s+(EXT4_FEATURE_{kind}_\w+)\s+(0x[0-9A-Fa-f]+)', header))
    expression = re.search(rf'#define\s+EXT4_FEATURE_{kind}_SUPP\s+\(([^)]+)\)', header)
    if expression is None:
        raise SystemExit(f'Cannot read original kernel ext4 {kind} support')
    supported[kind] = 0
    for name in re.findall(rf'EXT4_FEATURE_{kind}_\w+', expression.group(1)):
        supported[kind] |= values[name]
checks['ext4_features'] = {}

with tempfile.TemporaryDirectory(prefix='gta3xlwifi-system-layout-', dir=report_dir) as directory:
    raw = Path(directory) / 'system.raw.img'
    with image.open('rb') as stream:
        sparse = struct.unpack('<I', stream.read(4))[0] == 0xed26ff3a
    if sparse:
        subprocess.run([str(top / 'out/host/linux-x86/bin/simg2img'), str(image), str(raw)], check=True)
    else:
        raw = image

    def check_features(path, name):
        with path.open('rb') as stream:
            stream.seek(1024)
            superblock = stream.read(1024)
        if struct.unpack_from('<H', superblock, 56)[0] != 0xef53:
            raise SystemExit(f'{name}: not an ext4 filesystem')
        _, incompatible, readonly = struct.unpack_from('<III', superblock, 92)
        for kind, bits in (('INCOMPAT', incompatible), ('RO_COMPAT', readonly)):
            if bits & ~supported[kind]:
                raise SystemExit(f'{name}: unsupported kernel ext4 {kind} bits {bits & ~supported[kind]:#x}')
        checks['ext4_features'][name] = {'incompat': hex(incompatible), 'ro_compat': hex(readonly),
                                        'original_kernel_support_checked': True}

    check_features(raw, 'system.img')
    product = Path(images['images']['product.img']['path'])
    with product.open('rb') as stream:
        product_sparse = struct.unpack('<I', stream.read(4))[0] == 0xed26ff3a
    product_raw = Path(directory) / 'product.raw.img'
    if product_sparse:
        subprocess.run([str(top / 'out/host/linux-x86/bin/simg2img'), str(product), str(product_raw)], check=True)
    else:
        product_raw = product
    check_features(product_raw, 'product.img')

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
    setup = read_file('/system/lib/libprocessgroup_setup.so')
    if setup != (out / 'system/lib/libprocessgroup_setup.so').read_bytes():
        raise SystemExit('System image processgroup setup differs from the compiled library')
    if b'/system/etc/cgroups.gta3xlwifi.json' not in setup:
        raise SystemExit('System image processgroup setup lacks the device backend')
    checks['processgroup_setup_library_sha256'] = hashlib.sha256(setup).hexdigest()
    samsung_init = read_file('/init.exynos7904.rc')
    if re.search(rb'^\s*mount_all\s', samsung_init, re.M):
        raise SystemExit('Root Samsung init duplicates the stock vendor mount_all')
    checks['root_init_duplicate_mounts_absent'] = True
    device = top / 'device/samsung/gta3xlwifi'
    for member, source in (
        ('/fstab.exynos7904', device / 'rootdir/etc/fstab.exynos7904'),
        ('/init.exynos7904.rc', device / 'rootdir/init.exynos7904.rc'),
        ('/ueventd.exynos7904.rc', device / 'rootdir/ueventd.exynos7904.rc'),
        ('/system/system_ext/etc/init/init.gta3xlwifi.power.rc', device / 'rootdir/init.gta3xlwifi.power.rc'),
        ('/system/etc/cgroups.gta3xlwifi.json', device / 'configs/cgroups.gta3xlwifi.json'),
        ('/system/etc/task_profiles.gta3xlwifi.json', device / 'configs/task_profiles.gta3xlwifi.json'),
        ('/system/etc/init/init.gta3xlwifi.crypto.rc', device / 'rootdir/init.gta3xlwifi.crypto.rc'),
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
    if b'ro.kernel.ebpf.supported=false\n' not in props:
        raise SystemExit('Physical system image incorrectly advertises eBPF support')
    if b'ro.hardware=exynos7904\n' not in props:
        raise SystemExit('Physical system image lacks the Samsung init hardware selector')

checks['passed'] = True
(report_dir / 'native-layout-check.json').write_text(json.dumps(checks, indent=2) + '\n')
print(json.dumps(checks, indent=2))
