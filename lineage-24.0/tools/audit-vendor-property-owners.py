#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inventory direct private-property classifications, contexts and writer grants.

Read-only analysis, not a transitive attribute/effective-permission evaluator.
Suggestions require review; unreferenced or mixed-prefix labels are not assigned
an owner automatically. No policy, source, image or enforcement changes.
"""
import argparse
from collections import Counter, defaultdict
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
for n in ['baseline', 'contexts', 'output']:
    p.add_argument('--'+n, type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
cil, forms = load('stage-vendor-uwb-namespace'), load('stage-platform-policy-port')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
base = json.loads(a.baseline.read_text())
sources, declarations = {}, defaultdict(set)
members, writers = defaultdict(set), defaultdict(list)
vendor = None
for item in base['inputs']:
    path = Path(item['path'])
    assert sha(path) == item['sha256'], path
    sources[str(path)] = item['sha256']
    if path.name == 'vendor_sepolicy.cil':
        assert vendor is None
        vendor = path
    text = path.read_text()
    for kind, start, stop in forms.statements(text, cil.tokens):
        ts = cil.tokens(text[start:stop])
        if kind == 'type':
            declarations[path].add(ts[2][1])
        elif kind == 'typeattributeset':
            name = ts[2][1]
            expr = ts[4:-2]
            if ts[3][0] == '(' and ts[-2][0] == ')' and all(t[0] == 'symbol' and t[1] not in {'and', 'or', 'not', 'xor', 'all'} for t in expr):
                members[name].update(t[1] for t in expr)
        elif kind == 'allow' and len(ts) > 8 and ts[5][1] == 'property_service' and any(t[1] == 'set' for t in ts[6:]):
            writers[ts[3][1]].append({'source': ts[2][1], 'location': str(path)+':'+str(text.count('\n',0,start)+1), 'statement': text[start:stop]})
assert vendor
others = set.union(*(v for k, v in declarations.items() if k != vendor))
private = declarations[vendor]-others
properties = sorted(private & members['property_type'])
contexts = defaultdict(list)
for number, line in enumerate(a.contexts.read_text().splitlines(), 1):
    fields = line.partition('#')[0].split()
    if fields:
        assert len(fields) >= 2 and fields[1].startswith('u:object_r:')
        contexts[fields[1].split(':')[2]].append({'name': fields[0], 'line': number})
rows = []
for name in properties:
    owners = [n for n in ['system_property_type','product_property_type','vendor_property_type'] if name in members[n]]
    scopes = [n for n in ['vendor_internal_property_type','vendor_restricted_property_type','vendor_public_property_type'] if name in members[n]]
    names = contexts[name]
    prefixes = ('vendor.', 'ro.vendor.', 'persist.vendor.', 'ctl.vendor.', 'ctl.start$vendor.', 'ctl.stop$vendor.', 'ctl.restart$vendor.')
    namespace = 'unreferenced_label' if not names else 'vendor_prefixes_only' if all(x['name'].startswith(prefixes) for x in names) else 'legacy_or_mixed_prefixes'
    direct = writers[name]
    core_writers = sorted({x['source'] for x in direct if x['source'] in members['coredomain'] or x['source'].removesuffix('_30_0') in members['coredomain'] or x['source'] in {'domain', 'appdomain', 'coredomain'}})
    rows.append({'type': name, 'direct_owner_memberships': owners,
                 'direct_scope_memberships': scopes, 'context_namespace': namespace,
                 'contexts': names, 'direct_writer_grants': direct,
                 'direct_known_core_or_broad_writer_symbols': core_writers})
report = {'scope': __doc__, 'exclusive_vendor_private_property_types': len(rows),
          'missing_direct_owner_memberships': sum(not x['direct_owner_memberships'] for x in rows),
          'context_namespace_counts': dict(Counter(x['context_namespace'] for x in rows)),
          'rows': rows, 'input_sha256': sources | {str(a.contexts): sha(a.contexts), str(a.baseline): sha(a.baseline), str(Path(__file__)): sha(Path(__file__))},
          'effective_attribute_closure_or_permissions_proved': False,
          'automatic_classification_or_policy_edits': False, 'security_approved': False}
for path, expected in sources.items():
    assert sha(Path(path)) == expected
a.output.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({k:report[k] for k in ['exclusive_vendor_private_property_types','missing_direct_owner_memberships','context_namespace_counts']}))
