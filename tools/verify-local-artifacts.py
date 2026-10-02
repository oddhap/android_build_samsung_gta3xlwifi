#!/usr/bin/env python3
"""Check transferred files and the tablet's PIT; never write to the tablet."""
import hashlib
import json
import re
import struct
from pathlib import Path

root = Path(__file__).resolve().parents[1]
downloads = root / 'downloads'
native = downloads / 'native-rom'
report = json.loads((native / 'native-image-check.json').read_text())
if report['device'] != 'SM-T510':
    raise SystemExit('Unexpected device in build report')

def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

pit_text = (root / 'notes/device-test/pit.txt').read_text()
pit_sizes = {}
for entry in pit_text.split('--- Entry #')[1:]:
    name = re.search(r'^Partition Name: (\S+)$', entry, re.M)
    sectors = re.search(r'^Partition Block Count: (\d+)$', entry, re.M)
    if name and sectors:
        pit_sizes[name[1]] = int(sectors[1]) * 512

results = {}
for name, item in report['images'].items():
    path = native / 'images' / name
    partition = name.removesuffix('.img').upper()
    if pit_sizes.get(partition) != item['partition_bytes']:
        raise SystemExit(f'{name}: PIT differs from reviewed physical size')
    if path.stat().st_size != item['file_bytes'] or sha256(path) != item['sha256']:
        raise SystemExit(f'{name}: transfer size or SHA-256 mismatch')
    results[name] = {'sha256': item['sha256'], 'pit_bytes': pit_sizes[partition]}

package = native / Path(report['rom_zip']).name
if sha256(package) != report['rom_zip_sha256']:
    raise SystemExit('ROM ZIP: transfer SHA-256 mismatch')
results[package.name] = {'sha256': report['rom_zip_sha256']}

test_boot = downloads / 'test-boot'
vbmeta_report = json.loads((test_boot / 'provenance.json').read_text())
vbmeta = test_boot / 'vbmeta-disabled.img'
data = vbmeta.read_bytes()
if (sha256(vbmeta) != vbmeta_report['sha256'] or data[:4] != b'AVB0'
        or struct.unpack_from('>I', data, 120)[0] != 3
        or len(data) > pit_sizes.get('VBMETA', 0)):
    raise SystemExit('Test vbmeta: hash, format, flags or partition size mismatch')
results[vbmeta.name] = {'sha256': vbmeta_report['sha256'],
                       'pit_bytes': pit_sizes['VBMETA'], 'flags': 3}

for line in (downloads / 'stock-restore/SHA256SUMS').read_text().splitlines():
    expected, name = line.split(maxsplit=1)
    name = name.removeprefix('*')
    if sha256(downloads / 'stock-restore' / name) != expected:
        raise SystemExit(f'Stock restore file: {name}: SHA-256 mismatch')

destination = root / 'notes/device-test/local-artifact-check.json'
destination.write_text(json.dumps({'device': 'SM-T510', 'checks_passed': True,
    'hardware_tested': False, 'stock_restore_files_verified': True,
    'artifacts': results}, indent=2) + '\n')
print('Transferred artifacts, stock restore files and actual PIT sizes verified.')
print(destination)
