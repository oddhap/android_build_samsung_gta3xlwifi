#!/usr/bin/env python3
"""Inspect both packaged ABIs, including linker/ART inside their real APEXes."""
import argparse
import hashlib
import io
import json
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('target_files', type=Path)
parser.add_argument('--top', type=Path, default=Path('/srv/android/src/lineage-21.0-arm64'))
parser.add_argument('--report', type=Path, default=Path('/srv/android/artifacts/lineage-21-arm64/multilib-check.json'))
args = parser.parse_args()
checks = {'hardware_tested': False, 'files': {}, 'properties': {}}

def elf(data, name, bits):
    expected = (2, 183) if bits == 64 else (1, 40)
    if data[:4] != b'\x7fELF' or data[5] != 1 or (data[4], struct.unpack_from('<H', data, 18)[0]) != expected:
        raise RuntimeError(f'{name}: expected little-endian ARM{bits} ELF')
    checks['files'][name] = {'bits': bits, 'sha256': hashlib.sha256(data).hexdigest()}

with zipfile.ZipFile(args.target_files) as archive, tempfile.TemporaryDirectory(prefix='arm64-multilib-', dir=args.report.parent) as temp:
    names = set(archive.namelist())
    debugfs = args.top / 'out/host/linux-x86/bin/debugfs_static'
    def image_file(image, path):
        result = subprocess.run([str(debugfs), '-R', f'cat /{path}', str(image)], capture_output=True, check=True)
        return result.stdout
    vendor = Path(temp) / 'vendor.img'
    with archive.open('IMAGES/vendor.img') as source, vendor.open('wb') as destination:
        import shutil
        shutil.copyfileobj(source, destination)
    if vendor.read_bytes()[:4] == b'\x3a\xff\x26\xed':
        raw_vendor = Path(temp) / 'vendor.raw.img'
        subprocess.run([str(args.top / 'out/host/linux-x86/bin/simg2img'), str(vendor), str(raw_vendor)], check=True)
        vendor = raw_vendor
    for path in ('default.prop', 'build.prop', 'odm/etc/build.prop'):
        for line in image_file(vendor, path).decode().splitlines():
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                if key == 'ro.zygote' or '.cpu.abilist' in key:
                    checks['properties'][key] = value
    for bits, directory in ((32, 'lib'), (64, 'lib64')):
        for path in ('egl/libGLES_mali.so', 'hw/gralloc.exynos7904.so',
                     'hw/android.hardware.graphics.mapper@2.0-impl.so',
                     'hw/android.hardware.renderscript@1.0-impl.so', 'libion_exynos.so'):
            elf(image_file(vendor, f'{directory}/{path}'), f'VENDOR/{directory}/{path}', bits)
    for bits, directory in ((32, 'lib'), (64, 'lib64')):
        elf(archive.read(f'SYSTEM/bin/app_process{bits}'), f'SYSTEM/bin/app_process{bits}', bits)
        for library in ('libEGL.so', 'libGLESv2.so', 'libandroid.so', 'libnativewindow.so',
                        'libprocessgroup.so', 'libaudiohal@4.0.so'):
            name = f'SYSTEM/{directory}/{library}'
            elf(archive.read(name), name, bits)
        # Require both clients of the stock audio HIDL ABI and the cgroup fix.
        assert b'V4_0' in archive.read(f'SYSTEM/{directory}/libaudiohal@4.0.so')
        assert b'/system/etc/cgroups.gta3xlwifi.json' in archive.read(f'SYSTEM/{directory}/libprocessgroup.so')
        # Some private framework libraries are only installed for system_server.
        # Check every installed variant rather than inventing an ARM32 consumer.
        for library, marker in (
            ('libgpuwork.so', b'GPU BPF accounting unavailable on this kernel'),
            ('libmeminfo.so', b'ro.kernel.ebpf.supported'),
            ('libfs_mgr.so', b'ro.gta3xlwifi.ext4_project_quota'),
            ('libfs_mgr_binder.so', b'ro.gta3xlwifi.ext4_project_quota'),
            ('libprocessgroup_setup.so', b'/system/etc/cgroups.gta3xlwifi.json'),
        ):
            name = f'SYSTEM/{directory}/{library}'
            if name in names:
                data = archive.read(name)
                elf(data, name, bits)
                assert marker in data, name
    for name in sorted(names):
        if name.endswith(('build.prop', 'default.prop', 'prop.default')) and name.startswith(('SYSTEM/', 'ROOT/', 'PRODUCT/')):
            for line in archive.read(name).decode().splitlines():
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    if '.cpu.abilist' in key or key == 'ro.zygote':
                        previous = checks['properties'].get(key)
                        assert previous is None or previous == value, (name, key)
                        checks['properties'][key] = value
    assert checks['properties']['ro.system.product.cpu.abilist'] == 'arm64-v8a,armeabi-v7a,armeabi'
    assert checks['properties']['ro.system.product.cpu.abilist64'] == 'arm64-v8a'
    assert checks['properties']['ro.system.product.cpu.abilist32'] == 'armeabi-v7a,armeabi'
    assert checks['properties']['ro.vendor.product.cpu.abilist'] == 'arm64-v8a,armeabi-v7a,armeabi'
    assert checks['properties']['ro.vendor.product.cpu.abilist64'] == 'arm64-v8a'
    assert checks['properties']['ro.vendor.product.cpu.abilist32'] == 'armeabi-v7a,armeabi'
    assert checks['properties']['ro.zygote'] == 'zygote64_32'
    # Match init's real priority; Samsung ODM otherwise hides ARM64 at boot.
    source_code = (args.top/'system/core/init/property_service.cpp').read_text()
    initializer = source_code.split('static void property_initialize_ro_cpu_abilist() {',1)[1]
    order = initializer.split('const char* kAbilistSources[] = {',1)[1].split('};',1)[0]
    import re
    sources = re.findall(r'"([a-z]+)"', order)
    assert sources == ['product', 'odm', 'vendor', 'system'], sources
    props = checks['properties']
    if props.get('ro.product.cpu.abilist'):
        selected = 'explicit'
        effective = {suffix: props.get('ro.product.cpu.abilist'+suffix, '')
                     for suffix in ('', '32', '64')}
    else:
        selected = next(source for source in sources if any(
            props.get(f'ro.{source}.product.cpu.abilist{bits}') for bits in ('32', '64')))
        effective = {bits: props.get(f'ro.{selected}.product.cpu.abilist{bits}', '')
                     for bits in ('32', '64')}
        effective[''] = ','.join(value for value in (effective['64'], effective['32']) if value)
    assert effective == {'': 'arm64-v8a,armeabi-v7a,armeabi',
                         '32': 'armeabi-v7a,armeabi', '64': 'arm64-v8a'}, (selected, effective)
    checks['effective_cpu_abilist'] = effective
    checks['cpu_abilist_source'] = selected
    init = archive.read('SYSTEM/etc/init/hw/init.zygote64_32.rc')
    assert b'import /system/etc/init/hw/init.zygote64.rc' in init
    assert b'/system/bin/app_process32' in init
    primary_init = archive.read('SYSTEM/etc/init/hw/init.zygote64.rc')
    assert b'service zygote /system/bin/app_process64' in primary_init
    assert b'--start-system-server' in primary_init
    crypto = archive.read('SYSTEM/etc/init/init.gta3xlwifi.crypto.rc')
    for bits in (32, 64):
        assert f'exec_start boringssl_self_test{bits}'.encode() in crypto
        assert f'exec_start boringssl_self_test_apex{bits}'.encode() in crypto
    for apex, paths in (
        ('com.android.runtime', [('bin/linker', 32), ('bin/linker64', 64),
                                 ('lib/bionic/libc.so', 32), ('lib64/bionic/libc.so', 64)]),
        ('com.android.art', [('lib/libart.so', 32), ('lib64/libart.so', 64)]),
    ):
        matches = [n for n in names if n in (f'SYSTEM/apex/{apex}.apex', f'SYSTEM/apex/{apex}.capex')]
        assert len(matches) == 1, (apex, matches)
        package = zipfile.ZipFile(io.BytesIO(archive.read(matches[0])))
        if 'original_apex' in package.namelist():
            package = zipfile.ZipFile(io.BytesIO(package.read('original_apex')))
        payload = Path(temp) / f'{apex}.img'
        payload.write_bytes(package.read('apex_payload.img'))
        for path, bits in paths:
            elf(image_file(payload, path), f'{apex}/{path}', bits)
    assert not any('gta3xlwifi_abi_probe' in name or 'gta3xlwifi_hardware_probe' in name
                   for name in names), 'Test APK included in ROM'
    # Preserve the WebView provider and both native ABIs while relieving product.
    webviews = [name for name in names if name.endswith('/webview.apk')]
    assert webviews == ['SYSTEM/app/webview/webview.apk'], webviews
    with zipfile.ZipFile(io.BytesIO(archive.read(webviews[0]))) as webview:
        for abi, bits in (('armeabi-v7a', 32), ('arm64-v8a', 64)):
            library = f'lib/{abi}/libwebviewchromium.so'
            elf(webview.read(library), f'{webviews[0]}!{library}', bits)
checks['passed'] = True
args.report.write_text(json.dumps(checks, indent=2) + '\n')
print(json.dumps(checks, indent=2))
