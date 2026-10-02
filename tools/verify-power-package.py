#!/usr/bin/env python3
"""Check the exact power integration packaged by the completed native ROM build."""
import hashlib
import json
import re
import zipfile
from pathlib import Path
root = Path('/srv/android')
top = root / 'src/lineage-19.1'
out = top / 'out/target/product/gta3xlwifi'
report = json.loads((root / 'artifacts/native-power-image-check.json').read_text())
target_files = out / 'obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files-eng.builder.zip'
checks = {}
with zipfile.ZipFile(target_files) as archive:
    names = archive.namelist()
    member = 'SYSTEM/system_ext/etc/init/init.gta3xlwifi.power.rc'
    packaged_init = archive.read(member)
    source_init = (top / 'device/samsung/gta3xlwifi/rootdir/init.gta3xlwifi.power.rc').read_bytes()
    if packaged_init != source_init:
        raise SystemExit('Packaged power init differs from reviewed source')
    checks['loaded_init_member'] = member
    checks['loaded_init_sha256'] = hashlib.sha256(packaged_init).hexdigest()
    if any('android.hardware.power-service.gta3xlwifi' in name for name in names):
        raise SystemExit('Obsolete experimental HAL override still packaged')
    library = archive.read('SYSTEM/lib/libandroid_servers.so')
    if library[:5] != b'\x7fELF\x01':
        raise SystemExit('Unexpected system_server native library ABI')
    for marker in (b'Bounded CPU/GPU boost ready', b'gta3xlwifi_cluster0_min',
                   b'gta3xlwifi_cluster1_min', b'gta3xlwifi_min_lock'):
        if marker not in library:
            raise SystemExit(f'Native library lacks {marker!r}')
    checks['native_library_sha256'] = hashlib.sha256(library).hexdigest()
    policy = archive.read('SYSTEM/system_ext/etc/selinux/system_ext_sepolicy.cil')
    if b'/11500000.mali/gta3xlwifi_min_lock' not in policy:
        raise SystemExit('GPU endpoint label missing from packaged SELinux policy')
    if b'/11500000.mali/dvfs_min_lock' in policy:
        raise SystemExit('Stock GPU endpoint was unexpectedly relabeled')
    checks['system_ext_policy_sha256'] = hashlib.sha256(policy).hexdigest()
    systemui_members = [name for name in names if name.endswith('/SystemUI/SystemUI.apk')]
    if len(systemui_members) != 1:
        raise SystemExit(f'Unexpected SystemUI APK members: {systemui_members}')
    checks['systemui_member'] = systemui_members[0]
    apk = archive.read(systemui_members[0])
    checks['systemui_apk_sha256'] = hashlib.sha256(apk).hexdigest()
    if checks['systemui_apk_sha256'] != '98889637bb05eb3f0020bed7b9a9f9bc2bd9c6172db232fe3c23f112f919cefc':
        raise SystemExit('Reviewed SystemUI fix APK changed unexpectedly')
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
(root / 'artifacts/native-power-package-check.json').write_text(json.dumps(checks, indent=2) + '\n')
print(json.dumps(checks, indent=2))
