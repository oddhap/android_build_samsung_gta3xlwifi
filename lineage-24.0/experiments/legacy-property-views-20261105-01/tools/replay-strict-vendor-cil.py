#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay strict inputs with vendor CIL and an optional explicit platform CIL proposal."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
for n in ['baseline', 'vendor-cil', 'output']:
    p.add_argument('--'+n, type=Path, required=True)
p.add_argument('--platform-cil', type=Path)
a = p.parse_args()
spec=importlib.util.spec_from_file_location('diagnostics',Path(__file__).with_name('policy-diagnostics.py'))
diagnostics=importlib.util.module_from_spec(spec);spec.loader.exec_module(diagnostics)
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
replacements = {str(vendor[0]): a.vendor_cil.resolve()}
if a.platform_cil:
    platform = [Path(x['path']) for x in base['inputs'] if Path(x['path']).name == 'plat_sepolicy.cil']
    assert len(platform) == 1
    replacements[str(platform[0])] = a.platform_cil.resolve()
replacement_hashes = {str(p): sha(p) for p in replacements.values()}
out.mkdir(parents=True)
command = [str(replacements[x]) if x in replacements else x for x in command]
command[command.index('-o')+1] = str(out/'strict.policy')
result = subprocess.run(command, capture_output=True, text=True)
log=result.stdout+result.stderr
(out/'strict.log').write_text(log)
problems=diagnostics.blocks(log)
report = copy.deepcopy(base)
report.pop('checked_at_utc', None)
report['passed_strict'] = result.returncode == 0
report['strict_diagnostic_counts']={'normal':sum(x['kind']=='neverallow' for x in problems),
                                  'extended':sum(x['kind']!='neverallow' for x in problems),
                                  'total':len(problems)}
for item in report['inputs']:
    if item['path'] in replacements:
        path = replacements[item['path']]
        item.update(path=str(path), sha256=replacement_hashes[str(path)])
report['results'] = [{'mode':'strict','exit_code':result.returncode,'neverallow_checks_enabled':True,'command':command}]
if result.returncode == 0:
    report['results'][0]['compiled_policy_sha256'] = sha(out/'strict.policy')
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
for item in base['inputs']:
    assert sha(Path(item['path'])) == item['sha256']
assert sha(a.vendor_cil) == replacement_hash and sha(Path(command[0])) == base['compiler_sha256']
for path, expected in replacement_hashes.items():
    assert sha(Path(path)) == expected
print('Strict compiler exit:', result.returncode, '; diagnostics:',report['strict_diagnostic_counts'])
assert result.returncode in [0,255]
assert result.returncode==0 or problems,'Compiler failed without assertion diagnostics; inspect tool/link error'
