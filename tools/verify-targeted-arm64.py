#!/usr/bin/env python3
"""Check compiled multilib outputs and standalone test APKs before hardware use."""
import hashlib
import json
import struct
import zipfile
from pathlib import Path

top = Path('/srv/android/src/lineage-21.0-arm64')
out = top / 'out/target/product/gta3xlwifi'
report = {'hardware_tested': False, 'files': {}, 'test_apks': {}}

def elf(data, path, bits):
    assert data[:4] == b'\x7fELF' and data[5] == 1, path
    assert data[4] == (2 if bits == 64 else 1), path
    assert struct.unpack_from('<H', data, 18)[0] == (183 if bits == 64 else 40), path
    report['files'][str(path)] = {'bits': bits, 'sha256': hashlib.sha256(data).hexdigest()}

elf((out/'system/bin/init').read_bytes(), 'system/bin/init', 64)
for bits, directory in ((32, 'lib'), (64, 'lib64')):
    for library in ('libEGL.so', 'libnativewindow.so', 'libaudiohal.so', 'libaudiohal@4.0.so',
                    'libprocessgroup.so', 'libprocessgroup_setup.so', 'libgpuwork.so',
                    'libmeminfo.so', 'libfs_mgr.so', 'libfs_mgr_binder.so', 'libandroid_servers.so'):
        path = Path('system') / directory / library
        data = (out/path).read_bytes()
        elf(data, path, bits)
        markers = {
            'libaudiohal@4.0.so': [b'V4_0'],
            'libprocessgroup.so': [b'/system/etc/cgroups.gta3xlwifi.json'],
            'libprocessgroup_setup.so': [b'/system/etc/cgroups.gta3xlwifi.json'],
            'libgpuwork.so': [b'GPU BPF accounting unavailable on this kernel'],
            'libmeminfo.so': [b'ro.kernel.ebpf.supported'],
            'libfs_mgr.so': [b'ro.gta3xlwifi.ext4_project_quota'],
            'libfs_mgr_binder.so': [b'ro.gta3xlwifi.ext4_project_quota'],
            'libandroid_servers.so': [b'Bounded CPU/GPU boost ready', b'gta3xlwifi_cluster0_min',
                                      b'gta3xlwifi_cluster1_min', b'gta3xlwifi_min_lock'],
        }
        assert all(marker in data for marker in markers.get(library, [])), path
helper = (out/'system/bin/gta3xlwifi_recovery_header_sync').read_bytes()
elf(helper, 'system/bin/gta3xlwifi_recovery_header_sync', 32)
phoff = struct.unpack_from('<I', helper, 28)[0]
phsize, phcount = struct.unpack_from('<HH', helper, 42)
assert phsize == 32 and phcount > 0
assert all(struct.unpack_from('<I', helper, phoff+i*phsize)[0] != 3 for i in range(phcount))
for bits, abi in ((32, 'armeabi-v7a'), (64, 'arm64-v8a')):
    name = f'gta3xlwifi_abi_probe{bits}'
    apks = list((out/'testcases'/name).rglob(f'{name}.apk'))
    assert len(apks) == 1, (name, apks)
    apk = apks[0]
    with zipfile.ZipFile(apk) as archive:
        assert 'classes.dex' in archive.namelist(), 'Test APK has no executable Java classes'
        libraries = [member for member in archive.namelist() if member.startswith('lib/') and member.endswith('.so')]
        assert f'lib/{abi}/libgta3xlwifi_abi_probe.so' in libraries
        assert libraries and all(member.startswith(f'lib/{abi}/') for member in libraries), libraries
        for member in libraries:
            elf(archive.read(member), name + '/' + member, bits)
    report['test_apks'][str(bits)] = {'path': str(apk), 'sha256': hashlib.sha256(apk.read_bytes()).hexdigest(), 'abi': abi}
    assert not (out/'system/app'/name).exists(), 'Test APK staged in system'
    assert not (out/'product/app'/name).exists(), 'Test APK staged in product'
report['helper_static_arm32'] = True
report['passed'] = True
Path('/srv/android/artifacts/lineage-21-arm64/targeted-abi-check.json').write_text(json.dumps(report, indent=2)+'\n')
print('Compiled ARM64/ARM32 libraries, static ARM32 recovery helper and separate test APKs verified.')
