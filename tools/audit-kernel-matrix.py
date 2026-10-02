#!/usr/bin/env python3
"""List config mismatches in generated FCM 3's 4.4 kernel requirements."""
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path('/srv/android')
config = {}
for line in (root / 'artifacts/kernel-smoke/config').read_text().splitlines():
    match = re.match(r'(CONFIG_\w+)=(.*)', line)
    if match:
        config[match[1]] = match[2].strip('"')
    match = re.match(r'# (CONFIG_\w+) is not set', line)
    if match:
        config[match[1]] = 'n'
matrix = ET.parse(root / 'src/lineage-19.1/out/target/product/gta3xlwifi/system/etc/vintf/compatibility_matrix.3.xml')
failures = []
for kernel in matrix.getroot().findall('kernel'):
    if not kernel.get('version', '').startswith('4.4.'):
        continue
    conditions = kernel.find('conditions')
    if conditions is not None and any(config.get(item.findtext('key'), 'n') != item.findtext('value') for item in conditions.findall('config')):
        continue
    for item in kernel.findall('config'):
        key = item.findtext('key')
        value = item.find('value')
        actual = config.get(key, 'n')
        # Report non-scalar values for manual review rather than assuming success.
        if value.get('type') not in ('tristate', 'string', 'int') or actual != value.text:
            failures.append({'key': key, 'expected': value.text, 'type': value.get('type'), 'actual': actual})
print(json.dumps(failures, indent=2))
(root / 'artifacts/kernel-matrix-mismatches.json').write_text(json.dumps(failures, indent=2) + '\n')
