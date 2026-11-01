#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only Android 16 Samsung system-root/ext4 checks, never a boot approval.
Usage: check-diagnostic-layout.py TOP ARCHIVE_REPORT NEW_OUTPUT_DIRECTORY
Unsparses verified images into new scratch files; does not mount or flash.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

LIMITS = {'boot.img': 33554432, 'recovery.img': 47185920,
          'system.img': 3196059648, 'product.img': 327155712,
          'vendor.img': 343932928, 'cache.img': 159383552}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def supported_features(top):
    header = (top / 'kernel/samsung/gta3xlwifi/fs/ext4/ext4.h').read_text().replace('\\\n', ' ')
    result = {}
    for kind in ('INCOMPAT', 'RO_COMPAT'):
        values = {name: int(value, 16) for name, value in re.findall(
            rf'#define\s+(EXT4_FEATURE_{kind}_\w+)\s+(0x[0-9A-Fa-f]+)', header)}
        match = re.search(rf'#define\s+EXT4_FEATURE_{kind}_SUPP\s+\(([^)]+)\)', header)
        if not match:
            raise ValueError('Cannot parse kernel supported ext4 features: ' + kind)
        bits = 0
        for name in re.findall(rf'EXT4_FEATURE_{kind}_\w+', match.group(1)):
            bits |= values[name]
        result[kind] = bits
    return result


def check(top, archive_report, output):
    archive = json.loads(archive_report.read_text())
    if not archive.get('archive_crc_passed'):
        raise ValueError('Verified target-files archive report required')
    for name, image in archive['images'].items():
        if digest(Path(image['path'])) != image['sha256']:
            raise ValueError('Stale/corrupt image evidence: ' + name)
        if name in LIMITS and image['expanded_bytes'] > LIMITS[name]:
            raise ValueError('Physical partition limit exceeded: ' + name)
    supported = supported_features(top)
    report = {'passed': False, 'hardware_tested': False, 'scope': 'Offline filesystem layout only',
              'snapshot': archive['snapshot'], 'archive_sha256': archive['archive_sha256'],
              'physical_partition_limits_passed': True, 'ext4_features': {}, 'files': {}}
    raw_images = {}
    tools = top / 'out/host/linux-x86/bin'
    for name in ('system.img', 'product.img', 'cache.img'):
        raw = output / name.replace('.img', '.raw.img')
        subprocess.run([str(tools / 'simg2img'), archive['images'][name]['path'], str(raw)],
                       check=True, timeout=180)
        raw_images[name] = raw
        with raw.open('rb') as stream:
            stream.seek(1024)
            sb = stream.read(1024)
        if struct.unpack_from('<H', sb, 56)[0] != 0xef53:
            raise ValueError('Not ext4: ' + name)
        _, incompatible, readonly = struct.unpack_from('<III', sb, 92)
        for kind, bits in (('INCOMPAT', incompatible), ('RO_COMPAT', readonly)):
            if bits & ~supported[kind]:
                raise ValueError(f'{name}: unsupported kernel ext4 {kind} bits {bits & ~supported[kind]:#x}')
        report['ext4_features'][name] = {'incompat': hex(incompatible), 'ro_compat': hex(readonly),
                                        'actual_kernel_source_support_checked': True}

    def debug(command):
        result = subprocess.run([str(tools / 'debugfs_static'), '-R', command,
                                 str(raw_images['system.img'])], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True, timeout=120)
        if b'File not found' in result.stderr or b'not a regular file' in result.stderr:
            raise ValueError('Missing/invalid system-root file: ' + command)
        return result.stdout

    if b'Fast link dest: "/system/bin/init"' not in debug('stat /init'):
        raise ValueError('System image lacks the required /init -> /system/bin/init')
    init = debug('cat /system/bin/init')
    if init[:5] != b'\x7fELF\x02' or struct.unpack_from('<H', init, 18)[0] != 183:
        raise ValueError('Actual system-root init is not ARM64 ELF')
    report['init_sha256'] = hashlib.sha256(init).hexdigest()
    report['system_as_root_init_checked'] = True
    device = top / 'device/samsung/gta3xlwifi'
    files = {
        '/fstab.exynos7904': device / 'rootdir/etc/fstab.exynos7904',
        '/init.exynos7904.rc': device / 'rootdir/init.exynos7904.rc',
        '/ueventd.exynos7904.rc': device / 'rootdir/ueventd.exynos7904.rc',
        '/system/etc/cgroups.gta3xlwifi.json': device / 'configs/cgroups.gta3xlwifi.json',
        '/system/etc/task_profiles.gta3xlwifi.json': device / 'configs/task_profiles.gta3xlwifi.json',
        '/system/etc/init/init.gta3xlwifi.crypto.rc': device / 'rootdir/init.gta3xlwifi.crypto.rc',
    }
    for name, source in files.items():
        data = debug('cat ' + name)
        if data != source.read_bytes():
            raise ValueError('System image differs from reviewed source: ' + name)
        report['files'][name] = hashlib.sha256(data).hexdigest()
    if re.search(rb'^\s*mount_all\s', debug('cat /init.exynos7904.rc'), re.M):
        raise ValueError('Root Samsung init duplicates vendor mount_all')
    for name in ('libfs_mgr.so', 'libprocessgroup.so', 'libprocessgroup_setup.so',
                 'libaudiohal.so', 'libaudiohal@4.0.so', 'libmeminfo.so'):
        data = debug('cat /system/lib64/' + name)
        compiled = top / 'out/target/product/gta3xlwifi/system/lib64' / name
        if data != compiled.read_bytes():
            raise ValueError('Image library differs from compiled output: ' + name)
        if name == 'libfs_mgr.so' and b'ro.gta3xlwifi.ext4_project_quota' not in data:
            raise ValueError('Image fs_mgr lacks quota capability guard')
        report['files']['/system/lib64/' + name] = hashlib.sha256(data).hexdigest()
    props = debug('cat /system/build.prop')
    properties = {}
    for line in props.decode().splitlines():
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        if key in properties and properties[key] != value:
            raise ValueError('Conflicting image property: ' + key)
        properties[key] = value
    for key, value in {'ro.build.version.release': '16', 'ro.gta3xlwifi.legacy_networking': 'true',
                       'ro.kernel.ebpf.supported': 'false', 'ro.gta3xlwifi.ext4_project_quota': 'false'}.items():
        if properties.get(key) != value:
            raise ValueError('Missing/incorrect image property: ' + key)
    report.update(passed=True, android_release='16', runtime_networking_validated=False,
                  selinux_runtime_validated=False, fbe_recovery_ota_validated=False,
                  installation_approved=False, tablet_modified=False)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('top', type=Path)
    parser.add_argument('archive_report', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    top = args.top.resolve()
    if output == top or top in output.parents:
        parser.error('Scratch output must be outside the Android source/output tree')
    output.mkdir(parents=True, exist_ok=False)
    try:
        report = check(args.top.resolve(), args.archive_report.resolve(), output)
    except (OSError, ValueError, KeyError, struct.error, subprocess.SubprocessError) as error:
        report = {'passed': False, 'error': str(error), 'hardware_tested': False}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
