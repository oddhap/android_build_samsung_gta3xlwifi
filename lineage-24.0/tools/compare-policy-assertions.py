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
diagnostic_parser = load('policy-diagnostics')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
checks = {'neverallow','neverallowx','neverallowxperm','mlsconstrain','constrain','mlsvalidatetrans','validatetrans'}


def inventory(report_path):
    report = json.loads(report_path.read_text())
    assert report['results'][0]['mode'] == 'strict' and '-N' not in report['results'][0]['command']
    assertions, av, permissive, other, symbols = Counter(), Counter(), Counter(), Counter(), set()
    for item in report['inputs']:
        path = Path(item['path'])
        assert sha(path) == item['sha256']
        text = path.read_text()
        symbols.update(t[1] for t in cil.tokens(text) if t[0] == 'symbol')
        for kind, start, stop in forms.statements(text, cil.tokens):
            key = ' '.join(t[1] for t in cil.tokens(text[start:stop]))
            if kind in checks | {'allow','allowx','allowxperm','typepermissive'}:
                (assertions if kind in checks else permissive if kind=='typepermissive' else av)[key] += 1
            else:
                other[key] += 1
    diagnostics = Counter()
    for block in diagnostic_parser.blocks(report_path.with_name('strict.log').read_text()):
        assertion = block['assertion']
        diagnostics[' '.join(t[1] for t in cil.tokens(assertion))] += 1
    return assertions, av, permissive, diagnostics, other, symbols


def allow_parts(statement):
    ts = [t[1] for t in cil.tokens(statement)]
    if (len(ts) < 11 or ts[:2] != ['(', 'allow'] or ts[4] != '(' or
            ts[6] != '(' or ts[-3:] != [')', ')', ')']):
        return None
    permissions = ts[7:-3]
    if not permissions or any(x in {'(', ')', 'not', 'and', 'or'} for x in permissions):
        return None
    return (ts[2], ts[3], ts[5]), frozenset(permissions)


old, new = inventory(a.baseline), inventory(a.candidate)
assert not (old[0]-new[0]), 'An assertion/constraint was removed'
permission_subsets, source_subsets, target_subsets = [], [], []
added_other = new[4]-old[4]
removed_other = old[4]-new[4]
old_allow = {}
for statement in old[1]:
    parsed = allow_parts(statement)
    if parsed:
        key, perms = parsed
        old_allow.setdefault(key, []).append((statement, perms))
for statement, count in (new[1]-old[1]).items():
    parsed = allow_parts(statement)
    assert parsed, 'An extended/noncanonical AV grant was added'
    triple, permissions = parsed
    match = next((s for s, perms in old_allow.get(triple, []) if permissions <= perms), None)
    if match:
        permission_subsets.append({'before': match, 'after': statement, 'occurrences': count})
        continue
    # A fresh source attribute is a subset only when its sole definition is a
    # direct intersection with the old source. Existing type/attribute/role
    # statements must remain unchanged; no new concrete types may be added.
    assert not removed_other, 'Intersection narrowing changed old declarations/expressions'
    fresh, definitions = set(), {}
    for extra in added_other:
        ts = [t[1] for t in cil.tokens(extra)]
        assert ts[1] in {'typeattribute','typeattributeset'}, 'Source narrowing added another statement kind'
        assert ts[2] not in old[5], 'Source narrowing writes an existing symbol'
        if ts[1] == 'typeattribute':
            fresh.add(ts[2])
        else:
            assert ts[2] not in definitions and added_other[extra] == 1
            definitions[ts[2]] = ts
    axis = 0 if triple[0] in fresh else 1
    assert triple[axis] in fresh and triple[axis] in definitions
    definition = definitions[triple[axis]]
    assert len(definition) == 9 and definition[3:5] == ['(', 'and'] and definition[-2:] == [')', ')']
    match = None
    for operand in definition[5:7]:
        key = list(triple)
        key[axis] = operand
        match = next((s for s, perms in old_allow.get(tuple(key), []) if permissions <= perms), None)
        if match:
            break
    assert match, 'No proved source/permission subset for added AV text'
    (source_subsets if axis == 0 else target_subsets).append({'before':match,'after':statement,'occurrences':count,
                           'intersection_definition':' '.join(definition)})
assert not (new[2]-old[2]), 'A permissive declaration was added'
report = {'scope': __doc__, 'baseline_assertion_constraint_records': sum(old[0].values()),
          'candidate_assertion_constraint_records': sum(new[0].values()),
          'removed_assertions_or_constraints': [],
          'added_assertions_or_constraints': dict(new[0]-old[0]),
          'added_av_grant_statements': [], 'removed_av_grant_statement_count':sum((old[1]-new[1]).values()),
          'permission_narrowed_allow_replacements': permission_subsets,
          'source_intersection_allow_replacements': source_subsets,
          'target_intersection_allow_replacements': target_subsets,
          'baseline_diagnostic_blocks':sum(old[3].values()), 'candidate_diagnostic_blocks':sum(new[3].values()),
          'resolved_diagnostic_records':dict(old[3]-new[3]), 'new_diagnostic_records':dict(new[3]-old[3]),
          'effective_permission_or_attribute_equivalence_proved': False,
          'input_sha256':{str(f):sha(f) for f in [a.baseline,a.candidate,Path(__file__),Path(__file__).with_name('policy-diagnostics.py')]}}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print('Assertions retained:',sum(old[0].values()),'; added:',sum((new[0]-old[0]).values()),'; diagnostic blocks:',sum(old[3].values()),'->',sum(new[3].values()))
