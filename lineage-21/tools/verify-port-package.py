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
target_files = out / 'obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files-eng.builder.zip'
checks = {'hardware_tested': False}
with zipfile.ZipFile(target_files) as archive:
    names = archive.namelist()
    if any('gta3xlwifi-network-probe' in name for name in names):
        raise SystemExit('Optional packet probe was included in the ROM')
    if any('android.hardware.power-service.gta3xlwifi' in name for name in names):
        raise SystemExit('Obsolete experimental Power HAL override was packaged')
    member = 'SYSTEM/system_ext/etc/init/init.gta3xlwifi.power.rc'
    packaged_init = archive.read(member)
    if packaged_init != (top / 'device/samsung/gta3xlwifi/rootdir/init.gta3xlwifi.power.rc').read_bytes():
        raise SystemExit('Packaged power init differs from the reviewed source')
    checks['power_init_sha256'] = hashlib.sha256(packaged_init).hexdigest()
    library = archive.read('SYSTEM/lib/libandroid_servers.so')
    if library[:5] != b'\x7fELF\x01':
        raise SystemExit('Unexpected system_server native library ABI')
    for marker in (b'Bounded CPU/GPU boost ready', b'gta3xlwifi_cluster0_min',
                   b'gta3xlwifi_cluster1_min', b'gta3xlwifi_min_lock'):
        if marker not in library:
            raise SystemExit(f'Native library lacks {marker!r}')
    checks['native_power_library_sha256'] = hashlib.sha256(library).hexdigest()
    policy = archive.read('SYSTEM/system_ext/etc/selinux/system_ext_sepolicy.cil')
    if b'/11500000.mali/gta3xlwifi_min_lock' not in policy:
        raise SystemExit('Private GPU label is missing')
    if b'/11500000.mali/dvfs_min_lock' in policy:
        raise SystemExit('Original GPU endpoint was unexpectedly relabeled')
    checks['system_ext_policy_sha256'] = hashlib.sha256(policy).hexdigest()
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
