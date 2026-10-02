#!/usr/bin/env python3
"""Run on the build VM after copying the reviewed device configuration there."""
import hashlib
import json
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path('/srv/android')
TOP = ROOT / 'src/lineage-19.1'
DEVICE = TOP / 'device/samsung/gta3xlwifi'
STOCK = ROOT / 'vendor-stock'
VENDOR = STOCK / 'extracted/vendor'
KERNEL = ROOT / 'artifacts/kernel-smoke'
PREBUILT = DEVICE / 'prebuilt'
CONFIG = DEVICE / 'configs'
PREBUILT.mkdir(parents=True, exist_ok=True)
CONFIG.mkdir(parents=True, exist_ok=True)

# Validate the source-built kernel and overlays before using them.
for line in (KERNEL / 'SHA256SUMS').read_text().splitlines():
    digest, name = line.split(maxsplit=1)
    data = (KERNEL / name.lstrip('*')).read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError(f'Kernel artifact checksum mismatch: {name}')
shutil.copy2(KERNEL / 'Image', PREBUILT / 'Image')
vendor_digest = hashlib.sha256((STOCK / 'images/vendor.img').read_bytes()).hexdigest()
if vendor_digest != '4cc684231b4a1c355169cea61b4ea5196401bc5f68c7f74a32c1ec290abc0006':
    raise RuntimeError('Stock vendor image differs from the verified T510XXU5CWA1 image')
shutil.copy2(STOCK / 'images/vendor.img', PREBUILT / 'vendor.img')

# Build a DTBO container from our compiled gta3xlwifi overlays while retaining
# the hardware revision selectors read from the verified Samsung DTBO table.
original = (STOCK / 'images/dtbo.img').read_bytes()
magic, total, header_size, entry_size, count, entries_offset, page_size, version = struct.unpack_from('>8I', original)
assert magic == 0xd7b7ab1e and count == 2 and version == 0
command = ['python3', str(TOP / 'system/libufdt/utils/src/mkdtboimg.py'), 'create',
           str(PREBUILT / 'dtbo.img'), f'--page_size={page_size}', '--version=0']
comparisons = []
for index, revision in enumerate(('03', '04')):
    size, offset, dt_id, rev, *custom = struct.unpack_from('>8I', original, entries_offset + index * entry_size)
    overlay = KERNEL / f'dts/exynos/dtbo/exynos7904-gta3xlwifi_eur_open_{revision}.dtbo'
    comparisons.append({'revision': revision, 'same_as_stock': overlay.read_bytes() == original[offset:offset + size]})
    command += [str(overlay), f'--id={dt_id}', f'--rev={rev}']
    command += [f'--custom{i}={value}' for i, value in enumerate(custom)]
subprocess.run(command, check=True)

shutil.copy2(VENDOR / 'etc/vintf/manifest.xml', CONFIG / 'manifest.xml')
shutil.copy2(VENDOR / 'etc/vintf/compatibility_matrix.xml', CONFIG / 'device_matrix.xml')
shutil.copy2(VENDOR / 'ueventd.rc', DEVICE / 'rootdir/ueventd.exynos7904.rc')
with (DEVICE / 'rootdir/ueventd.exynos7904.rc').open('a') as stream:
    stream.write('\n# Separate framework CPU QoS endpoints.\n'
                 '/dev/gta3xlwifi_cluster0_min 0660 system system\n'
                 '/dev/gta3xlwifi_cluster1_min 0660 system system\n')


# Register the original non-AOSP HAL names for framework compatibility checks.
# Standard Android HAL requirements remain in the unmodified platform matrices.
matrix = ET.Element('compatibility-matrix', {'version': '1.0', 'type': 'framework'})
manifest_paths = sorted((VENDOR / 'etc/vintf').rglob('*.xml'))
seen = set()
for path in manifest_paths:
    document = ET.parse(path).getroot()
    if document.tag != 'manifest':
        continue
    for hal in document.findall('hal'):
        name = hal.findtext('name', '')
        if not name.startswith(('vendor.', 'com.')):
            continue
        # Empty override entries disable a HAL (the Wi-Fi model disables radio).
        if hal.get('override') == 'true' and not hal.findall('version') and not hal.findall('fqname'):
            continue
        key = ET.tostring(hal)
        if key in seen:
            continue
        seen.add(key)
        target = ET.SubElement(matrix, 'hal', {'format': hal.get('format', 'hidl'), 'optional': 'true'})
        ET.SubElement(target, 'name').text = name
        for child in hal:
            if child.tag in ('version', 'interface'):
                target.append(ET.fromstring(ET.tostring(child)))
        # Manifest fqname syntax differs from matrix interface syntax. AIDL
        # version 1 is implicit when absent in the original Android 11 manifest.
        if not target.findall('interface'):
            interfaces = {}
            for fqname in hal.findall('fqname'):
                value = fqname.text or ''
                if '::' in value:
                    version, value = value.split('::', 1)
                    if not target.findall('version'):
                        ET.SubElement(target, 'version').text = version.lstrip('@')
                interface, instance = value.split('/', 1)
                interfaces.setdefault(interface, []).append(instance)
            if target.get('format') == 'aidl' and not target.findall('version'):
                ET.SubElement(target, 'version').text = '1'
            for interface, instances in interfaces.items():
                item = ET.SubElement(target, 'interface')
                ET.SubElement(item, 'name').text = interface
                for instance in instances:
                    ET.SubElement(item, 'instance').text = instance
        if not target.findall('interface'):
            raise RuntimeError(f'No interfaces found for vendor HAL {name}')
ET.indent(matrix)
ET.ElementTree(matrix).write(CONFIG / 'framework_matrix.xml', encoding='unicode', xml_declaration=True)

# Supply the stock vendor compatibility metadata to target-files packaging.
# Original HAL binaries are in the vendor image, not copied into system.
copied = []
for relative_dir in ('etc/vintf', 'etc/selinux'):
    for source in sorted((VENDOR / relative_dir).rglob('*')):
        if not source.is_file():
            continue
        relative = source.relative_to(VENDOR)
        destination = CONFIG / 'stock' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        # The build system assembles the root VINTF manifest/matrix itself.
        if relative.parts[:2] == ('etc', 'vintf'):
            continue
        copied.append(f'    device/samsung/gta3xlwifi/configs/stock/{relative}:$(TARGET_COPY_OUT_VENDOR)/{relative}')
(CONFIG / 'vendor-metadata.mk').write_text('# Generated from verified T510XXU5CWA1 vendor image.\nPRODUCT_COPY_FILES += \\\n' + ' \\\n'.join(copied) + '\n')

provenance = {
    'device': 'SM-T510/gta3xlwifi',
    'kind': 'native device-specific development build',
    'kernel_source_commit': (KERNEL / 'source-commit.txt').read_text().strip(),
    'kernel_sha256': hashlib.sha256((PREBUILT / 'Image').read_bytes()).hexdigest(),
    'vendor_sha256': hashlib.sha256((PREBUILT / 'vendor.img').read_bytes()).hexdigest(),
    'dtbo_sha256': hashlib.sha256((PREBUILT / 'dtbo.img').read_bytes()).hexdigest(),
    'stock_firmware': 'T510XXU5CWA1/T510OXM5CVG2',
    'overlay_comparison': comparisons,
    'google_apps_added': False,
    'hardware_tested': False,
}
(PREBUILT / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
print(json.dumps(provenance, indent=2))
