#!/usr/bin/env python3
"""Inventory the original HAL dependencies; never execute vendor binaries."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path('/srv/android')
VENDOR = ROOT / 'vendor-stock/extracted/vendor'
SYSTEM = ROOT / 'vendor-stock/extracted/system-lib/lib'
TOP = ROOT / 'src/lineage-19.1'
vendor_names = {p.name for p in VENDOR.rglob('*.so')}
system_names = {p.name for p in SYSTEM.rglob('*.so')}
dependencies = {}
errors = []
for file in sorted(VENDOR.rglob('*')):
    if not file.is_file():
        continue
    try:
        with file.open('rb') as stream:
            magic = stream.read(4)
    except OSError as error:
        errors.append({'path': str(file), 'error': str(error)})
        continue
    if magic != b'\x7fELF':
        continue
    result = subprocess.run(['readelf', '-d', str(file)], text=True, capture_output=True)
    if result.returncode:
        errors.append({'path': str(file.relative_to(VENDOR)), 'error': result.stderr})
        continue
    needed = re.findall(r'\(NEEDED\).*\[(.*?)\]', result.stdout)
    for library in needed:
        if library not in vendor_names:
            dependencies.setdefault(library, []).append(str(file.relative_to(VENDOR)))

report = {'non_vendor_dependencies': dependencies,
          'absent_from_original_system': sorted(set(dependencies) - system_names),
          'errors': errors}
destination = ROOT / 'artifacts/vendor-elf-dependencies.json'
destination.write_text(json.dumps(report, indent=2) + '\n')
print('HAL dependencies outside vendor:', len(dependencies))
print('Absent from original system:', report['absent_from_original_system'])
print('Read errors:', len(errors))
