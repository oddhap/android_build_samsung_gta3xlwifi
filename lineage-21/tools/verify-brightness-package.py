#!/usr/bin/env python3
"""Verify the minimum-backlight mapping is present in signed services bytecode."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

p = argparse.ArgumentParser()
p.add_argument('target_files', type=Path)
p.add_argument('--dexdump', type=Path, required=True)
p.add_argument('--report', type=Path, required=True)
a = p.parse_args()
descriptor = 'Lcom/android/server/display/DisplayDeviceConfig;'
found = []
with zipfile.ZipFile(a.target_files) as target:
    props = dict(line.split('=', 1) for line in target.read('SYSTEM/build.prop')
                 .decode().splitlines() if '=' in line and not line.startswith('#'))
    jar_bytes = target.read('SYSTEM/framework/services.jar')
    with zipfile.ZipFile(io.BytesIO(jar_bytes)) as jar, tempfile.TemporaryDirectory() as tmp:
        for name in jar.namelist():
            if not re.fullmatch(r'classes\d*\.dex', name):
                continue
            dex = Path(tmp) / name
            dex.write_bytes(jar.read(name))
            process = subprocess.Popen([str(a.dexdump), '-d', str(dex)],
                                       stdout=subprocess.PIPE, text=True, errors='replace')
            in_class = False
            method = None
            for line in process.stdout:
                if 'Class descriptor' in line:
                    in_class = descriptor in line
                if method is not None and (re.match(r'\s*#\d+\s*:', line)
                                           or line.startswith('Class #')):
                    found.append(''.join(method))
                    method = None
                if in_class and re.search(r"name\s*:\s*'setSimpleMappingStrategyValues'", line):
                    method = []
                if method is not None:
                    method.append(line)
            if method is not None:
                found.append(''.join(method))
            assert process.wait() == 0, 'DEX disassembly failed'
assert len(found) == 1, 'Expected exactly one simple-mapping method'
method = found[0]
for field in ('mBacklightMinimum', 'mBacklightMaximum',
              'mBrightnessToBacklightSpline', 'mBacklightToBrightnessSpline'):
    assert field in method, 'Missing signed mapping field: ' + field
assert method.count('createSpline') == 2, 'Both mapping directions must be present'
report = {'passed': True, 'build_incremental': props['ro.build.version.incremental'],
          'signed_services_jar_sha256': hashlib.sha256(jar_bytes).hexdigest(),
          'signed_dex_contains_minimum_and_maximum_backlight_mapping': True,
          'both_mapping_directions_present': True, 'hardware_tested': False}
a.report.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
