#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify isolated policy-input changes and full before/after source audits."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
for n in ['baseline', 'candidate', 'output']:
    p.add_argument('--'+n, type=Path, required=True)
a = p.parse_args()
spec=importlib.util.spec_from_file_location('diagnostics',Path(__file__).with_name('policy-diagnostics.py'))
diagnostic_parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(diagnostic_parser)
if a.output.exists():
    raise FileExistsError(a.output)
baseline = json.loads(a.baseline.read_text())
current = json.loads((a.candidate/'strict/report.json').read_text())
assert baseline['compiler_sha256'] == current['compiler_sha256']
assert len(baseline['inputs']) == len(current['inputs'])
changes = []
for old, new in zip(baseline['inputs'], current['inputs']):
    assert Path(old['path']).name == Path(new['path']).name
    if old['sha256'] != new['sha256']:
        name = Path(old['path']).name
        assert name in {'plat_pub_versioned.cil', 'vendor_sepolicy.cil', '30.0.compat.cil', 'plat_sepolicy.cil'}
        changes.append(name)
    else:
        assert Path(new['path']).read_bytes() == Path(old['path']).read_bytes()
    assert hashlib.sha256(Path(new['path']).read_bytes()).hexdigest() == new['sha256']
before, after = [json.loads((a.candidate/f'source-{phase}.json').read_text()) for phase in ['before', 'after']]
for audit in [before, after]:
    assert audit['passed'] and audit['project_count'] == 1243 and audit['reviewed_patch_count'] == 15
    audit.pop('checked_at_utc')
assert before == after
def diagnostics(log):
    blocks = diagnostic_parser.blocks(log.read_text())
    return Counter('current_platform' if ' from system/sepolicy/' in b['location']
                   else Path(b['location'].split(':')[0]).name for b in blocks)
report = {'owner_decision_2026_11_05': 'Retain Android17 and Samsung vendor assertions; port the old platform component.',
          'changed_ordered_policy_inputs': changes,
          'all_other_inputs_and_compiler_byte_identical': True,
          'full_source_before_after_audits_match': True,
          'projects': 1243, 'exact_patches': 15,
          'baseline_diagnostic_origins': dict(diagnostics(a.baseline.with_name('strict.log'))),
          'candidate_diagnostic_origins': dict(diagnostics(a.candidate/'strict/strict.log')),
          'strict_result': current['results'][0], 'strict_passed': current['passed_strict'],
          'effective_permissions_compared': False,
          'runtime_validated': False, 'security_approved': False, 'flash_ready': False,
          'evidence_sha256': {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in
                              [a.baseline, a.candidate/'strict/report.json', a.candidate/'metadata/report.json',
                               a.candidate/'source-before.json', a.candidate/'source-after.json', Path(__file__)]}}
a.output.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({k: report[k] for k in ['changed_ordered_policy_inputs', 'candidate_diagnostic_origins', 'strict_passed']}))
