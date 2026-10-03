#!/usr/bin/env python3
"""Inspect the completed Android 14 target-files and OTA without touching a device."""
import hashlib
import json
import re
import zipfile
from pathlib import Path

root = Path('/srv/android')
top = root / 'src/lineage-21.0'
out = top / 'out/target/product/gta3xlwifi'
report = json.loads((root / 'artifacts/lineage-21/native-image-check.json').read_text())
target_files = out / 'obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files'
checks = {'hardware_tested': False}
digest = hashlib.sha256()
with Path(report['rom_zip']).open('rb') as stream:
    while chunk := stream.read(4 * 1024 * 1024):
        digest.update(chunk)
if digest.hexdigest() != report['rom_zip_sha256']:
    raise SystemExit('ZIP report is stale; run verify-native-images.py first')

class TargetFilesTree:
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def namelist(self):
        return [p.relative_to(target_files).as_posix() for p in target_files.rglob('*') if p.is_file()]
    def read(self, name):
        return (target_files / name).read_bytes()

with TargetFilesTree() as archive:
    names = archive.namelist()
    if any(probe in name for name in names
           for probe in ('gta3xlwifi-network-probe', 'gta3xlwifi-cgroup-probe')):
        raise SystemExit('Optional test probe was included in the ROM')
    if any('android.hardware.power-service.gta3xlwifi' in name for name in names):
        raise SystemExit('Obsolete experimental Power HAL override was packaged')
    member = 'SYSTEM/system_ext/etc/init/init.gta3xlwifi.power.rc'
    packaged_init = archive.read(member)
    if packaged_init != (top / 'device/samsung/gta3xlwifi/rootdir/init.gta3xlwifi.power.rc').read_bytes():
        raise SystemExit('Packaged power init differs from the reviewed source')
    checks['power_init_sha256'] = hashlib.sha256(packaged_init).hexdigest()
    library = archive.read('SYSTEM/lib/libandroid_servers.so')
    if library[:5] != b'\x7fELF\x01' or library[18:20] != b'\x28\x00':
        raise SystemExit('Unexpected system_server native library ABI')
    for marker in (b'Bounded CPU/GPU boost ready', b'gta3xlwifi_cluster0_min',
                   b'gta3xlwifi_cluster1_min', b'gta3xlwifi_min_lock'):
        if marker not in library:
            raise SystemExit(f'Native library lacks {marker!r}')
    checks['native_power_library_sha256'] = hashlib.sha256(library).hexdigest()
    processgroups = archive.read('SYSTEM/lib/libprocessgroup.so')
    if b'/system/etc/cgroups.gta3xlwifi.json' not in processgroups:
        raise SystemExit('Packaged processgroup library lacks the device v1 backend')
    checks['processgroup_library_sha256'] = hashlib.sha256(processgroups).hexdigest()
    audio4 = archive.read('SYSTEM/lib/libaudiohal@4.0.so')
    if audio4[:5] != b'\x7fELF\x01' or audio4[18:20] != b'\x28\x00':
        raise SystemExit('Stock audio HIDL 4 client has the wrong ABI')
    if b'V4_0' not in audio4:
        raise SystemExit('Stock audio client lacks HIDL 4 interface symbols')
    checks['audio_hidl4_library_sha256'] = hashlib.sha256(audio4).hexdigest()
    gpuwork = archive.read('SYSTEM/lib/libgpuwork.so')
    if b'GPU BPF accounting unavailable on this kernel' not in gpuwork:
        raise SystemExit('GPU work library lacks the kernel capability guard')
    checks['gpuwork_library_sha256'] = hashlib.sha256(gpuwork).hexdigest()
    for target, source in (
        ('SYSTEM/etc/cgroups.gta3xlwifi.json', 'configs/cgroups.gta3xlwifi.json'),
        ('SYSTEM/etc/task_profiles.gta3xlwifi.json', 'configs/task_profiles.gta3xlwifi.json'),
        ('SYSTEM/etc/init/init.gta3xlwifi.crypto.rc', 'rootdir/init.gta3xlwifi.crypto.rc'),
    ):
        if archive.read(target) != (top / 'device/samsung/gta3xlwifi' / source).read_bytes():
            raise SystemExit(f'Packaged legacy boot configuration differs: {target}')
    policy = archive.read('SYSTEM/system_ext/etc/selinux/system_ext_sepolicy.cil')
    if b'/11500000.mali/gta3xlwifi_min_lock' not in policy:
        raise SystemExit('Private GPU label is missing')
    if b'/11500000.mali/dvfs_min_lock' in policy:
        raise SystemExit('Original GPU endpoint was unexpectedly relabeled')
    checks['system_ext_policy_sha256'] = hashlib.sha256(policy).hexdigest()
    profiles = json.loads(archive.read('SYSTEM/etc/task_profiles.gta3xlwifi.json'))
    for profile in profiles['Profiles']:
        cpu = [action['Params'] for action in profile['Actions']
               if action['Name'] == 'JoinCgroup' and action['Params']['Controller'] == 'cpu']
        if cpu != [{'Controller': 'cpu', 'Path': ''}]:
            raise SystemExit(f"Profile does not preserve the root RT budget: {profile['Name']}")
    checks['cpu_profiles_preserve_root_rt_budget'] = True
    contexts = archive.read('SYSTEM/system_ext/etc/selinux/system_ext_property_contexts').decode()
    expected = 'hwc.exynos.vsync_mode u:object_r:graphics_config_prop:s0 exact string'
    if expected not in contexts.splitlines():
        raise SystemExit('Exact legacy vsync property label is missing')
    checks['vsync_property_label'] = 'graphics_config_prop, exact string'
    props = archive.read('SYSTEM/build.prop').decode()
    values = dict(line.split('=', 1) for line in props.splitlines()
                  if '=' in line and not line.startswith('#'))
    if values.get('ro.build.version.release') != '14':
        raise SystemExit('Packaged platform is not Android 14')
    if values.get('ro.gta3xlwifi.legacy_networking') != 'true':
        raise SystemExit('Device legacy networking selector is missing')
    checks['android_release'] = values['ro.build.version.release']
    checks['platform_security_patch'] = values['ro.build.version.security_patch']
    systemui = [name for name in names if name.endswith('/SystemUI/SystemUI.apk')]
    if len(systemui) != 1:
        raise SystemExit(f'Unexpected SystemUI APKs: {systemui}')
    checks['systemui_apk_sha256'] = hashlib.sha256(archive.read(systemui[0])).hexdigest()
    # Google search/setup/payment packages are not part of this vanilla product.
    google_packages = ('GmsCore', 'PrebuiltGmsCore', 'GoogleServicesFramework',
                       'Phonesky', 'GoogleLoginService')
    if any(name.rsplit('/', 1)[-1].removesuffix('.apk') in google_packages for name in names):
        raise SystemExit('A Google services APK was included')
with zipfile.ZipFile(report['rom_zip']) as archive:
    script = archive.read('META-INF/com/google/android/updater-script').decode()
    partitions = set(re.findall(r'/dev/block/platform/13500000\.dwmmc0/by-name/([a-zA-Z0-9_]+)', script))
    if partitions != {'system', 'product', 'boot'}:
        raise SystemExit(f'Unexpected OTA partition references: {partitions}')
    if 'format(' in script or 'delete_recursive("/data' in script:
        raise SystemExit('Unexpected data formatting/deletion in OTA')
    checks['ota_partition_references'] = sorted(partitions)
checks['passed'] = True
checks['rom_zip_sha256'] = report['rom_zip_sha256']
(root / 'artifacts/lineage-21/port-package-check.json').write_text(json.dumps(checks, indent=2) + '\n')
print(json.dumps(checks, indent=2))
