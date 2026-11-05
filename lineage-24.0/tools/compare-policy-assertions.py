#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare complete CIL assertion inventories and strict diagnostic identities.

Text/token preservation is not effective attribute-membership or runtime proof.
Resolved diagnostic records do not mean assertions were removed.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p = argparse.ArgumentParser(description=__doc__)
for name in ['baseline', 'candidate', 'output']:
    p.add_argument('--'+name, type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
cil, forms = load('stage-vendor-uwb-namespace'), load('stage-platform-policy-port')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
checks = {'neverallow','neverallowx','neverallowxperm','mlsconstrain','constrain','mlsvalidatetrans','validatetrans'}


def inventory(report_path):
    report = json.loads(report_path.read_text())
    assert report['results'][0]['mode'] == 'strict' and '-N' not in report['results'][0]['command']
    assertions, av, permissive = Counter(), Counter(), Counter()
    for item in report['inputs']:
        path = Path(item['path'])
        assert sha(path) == item['sha256']
        text = path.read_text()
        for kind, start, stop in forms.statements(text, cil.tokens):
            if kind in checks | {'allow','allowx','allowxperm','typepermissive'}:
                key = ' '.join(t[1] for t in cil.tokens(text[start:stop]))
                (assertions if kind in checks else permissive if kind=='typepermissive' else av)[key] += 1
    diagnostics = Counter()
    for block in report_path.with_name('strict.log').read_text().split('neverallow check failed at ')[1:]:
        assertion = next(x.strip() for x in block.splitlines()[1:] if x.strip().startswith('(neverallow'))
        diagnostics[' '.join(t[1] for t in cil.tokens(assertion))] += 1
    return assertions, av, permissive, diagnostics


old, new = inventory(a.baseline), inventory(a.candidate)
assert not (old[0]-new[0]), 'An assertion/constraint was removed'
assert not (new[1]-old[1]), 'An AV grant statement was added'
assert not (new[2]-old[2]), 'A permissive declaration was added'
report = {'scope': __doc__, 'baseline_assertion_constraint_records': sum(old[0].values()),
          'candidate_assertion_constraint_records': sum(new[0].values()),
          'removed_assertions_or_constraints': [],
          'added_assertions_or_constraints': dict(new[0]-old[0]),
          'added_av_grant_statements': [], 'removed_av_grant_statement_count':sum((old[1]-new[1]).values()),
          'baseline_diagnostic_blocks':sum(old[3].values()), 'candidate_diagnostic_blocks':sum(new[3].values()),
          'resolved_diagnostic_records':dict(old[3]-new[3]), 'new_diagnostic_records':dict(new[3]-old[3]),
          'effective_permission_or_attribute_equivalence_proved': False,
          'input_sha256':{str(f):sha(f) for f in [a.baseline,a.candidate,Path(__file__)]}}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print('Assertions retained:',sum(old[0].values()),'; added:',sum((new[0]-old[0]).values()),'; diagnostic blocks:',sum(old[3].values()),'->',sum(new[3].values()))
