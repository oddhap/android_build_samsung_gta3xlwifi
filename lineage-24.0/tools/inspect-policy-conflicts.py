#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Repeat an exact strict policy check with complete verbose conflict diagnostics."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--report', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
base = json.loads(a.report.read_text())
command = list(base['results'][0]['command'])
assert base['results'][0]['mode'] == 'strict'
assert '-N' not in command and not base['passed_strict']
output = a.output.resolve()
assert not output.exists()
for item in base['inputs']:
    path = Path(item['path']).resolve()
    assert not output.is_relative_to(path.parent)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
inputs = {Path(x['path']): x['sha256'] for x in base['inputs']}
inputs[Path(command[0])] = base['compiler_sha256']
for path, expected in inputs.items():
    assert sha(path) == expected, path
output.mkdir(parents=True)
command[command.index('-o')+1] = str(output/'strict.policy')
command.insert(1, '-v')
result = subprocess.run(command, capture_output=True, text=True)
log = result.stdout+result.stderr
(output/'strict-verbose.log').write_text(log)
blocks = log.split('neverallow check failed at ')[1:]
conflicts = []
for block in blocks:
    lines = block.splitlines()
    assertion = next((x.strip() for x in lines[1:] if x.strip().startswith('(neverallow')), None)
    grants = []
    for i, line in enumerate(lines):
        if 'allow at ' in line:
            grants.append({'location': line.strip(), 'statement': lines[i+1].strip()})
    assert assertion and grants
    assert not any('Only first' in x for x in lines), 'Verbose output still truncated'
    conflicts.append({'assertion_location': lines[0], 'assertion': assertion, 'matching_grants': grants})
assert result.returncode == base['results'][0]['exit_code'] == 255
assert len(conflicts) == (a.report.with_name('strict.log').read_text().count('neverallow check failed at '))
for path, expected in inputs.items():
    assert sha(path) == expected, path
report = {'command': command, 'compiler_exit': result.returncode,
          'neverallow_checks_enabled': True, 'no_input_modified': True,
          'conflict_count': len(conflicts),
          'matching_grant_records': sum(len(x['matching_grants']) for x in conflicts),
          'conflicts': conflicts, 'input_sha256': {str(k): v for k, v in inputs.items()},
          'runner_sha256': sha(Path(__file__)), 'baseline_report_sha256': sha(a.report),
          'strict_passed': False, 'security_approved': False, 'flash_ready': False}
(output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
print('Complete strict conflict diagnostics:', len(conflicts), '; matching grant records:', report['matching_grant_records'])
