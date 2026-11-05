#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay exact strict compiler inputs with one isolated vendor CIL replacement."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
for n in ['baseline', 'vendor-cil', 'output']:
    p.add_argument('--'+n, type=Path, required=True)
a = p.parse_args()
base = json.loads(a.baseline.read_text())
command = list(base['results'][0]['command'])
assert base['results'][0]['mode'] == 'strict' and '-N' not in command
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(Path(command[0])) == base['compiler_sha256']
out = a.output.resolve()
assert not out.exists() and not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
vendor = [Path(x['path']) for x in base['inputs'] if Path(x['path']).name == 'vendor_sepolicy.cil']
assert len(vendor) == 1
for item in base['inputs']:
    assert sha(Path(item['path'])) == item['sha256']
    assert not out.is_relative_to(Path(item['path']).resolve().parent)
assert str(vendor[0]) in command
replacement_hash = sha(a.vendor_cil)
out.mkdir(parents=True)
command = [str(a.vendor_cil.resolve()) if x == str(vendor[0]) else x for x in command]
command[command.index('-o')+1] = str(out/'strict.policy')
result = subprocess.run(command, capture_output=True, text=True)
(out/'strict.log').write_text(result.stdout+result.stderr)
report = copy.deepcopy(base)
report.pop('checked_at_utc', None)
report['passed_strict'] = result.returncode == 0
for item in report['inputs']:
    if item['path'] == str(vendor[0]):
        item.update(path=str(a.vendor_cil.resolve()), sha256=replacement_hash)
report['results'] = [{'mode':'strict','exit_code':result.returncode,'neverallow_checks_enabled':True,'command':command}]
if result.returncode == 0:
    report['results'][0]['compiled_policy_sha256'] = sha(out/'strict.policy')
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
for item in base['inputs']:
    assert sha(Path(item['path'])) == item['sha256']
assert sha(a.vendor_cil) == replacement_hash and sha(Path(command[0])) == base['compiler_sha256']
print('Strict compiler exit:', result.returncode, '; diagnostics:', (result.stdout+result.stderr).count('neverallow check failed at '))
assert result.returncode in [0,255]
