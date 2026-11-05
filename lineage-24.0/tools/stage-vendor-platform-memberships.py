#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Port old platform classifications embedded in Samsung's versioned vendor CIL.

Only positive flat membership lists of current shared attributes are supported.
Android17 owns its concrete platform types; vendor-private and legacy-only type
memberships remain. All vendor assertions and AV rules stay byte-exact. Offline
proposal only: this does not establish effective-policy or runtime correctness.
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
for n in ['top', 'vendor', 'current-report', 'output']:
    p.add_argument('--'+n, type=Path, required=True)
a = p.parse_args()
top, vendor, output = a.top.resolve(), a.vendor.resolve(), a.output.resolve()
if output.exists() or output.is_relative_to(top) or output.is_relative_to(vendor):
    raise ValueError('Output must be new and outside preserved inputs')
cil, port = load('stage-vendor-uwb-namespace'), load('stage-platform-policy-port')
sha = lambda b: hashlib.sha256(b).hexdigest()
source = vendor/'etc/selinux'
original = {n: (source/n).read_bytes() for n in cil.FILES}
if sha(original['vendor_sepolicy.cil']) != '18d979058fcffc42b06ccea8fd60b81dd506e8b06adb17804c72d277aa52b227':
    raise ValueError('Unreviewed vendor parent')
attrs, types, inputs = set(), set(), []
for item in json.loads(a.current_report.read_text())['inputs']:
    path = Path(item['path'])
    if path.name not in {'plat_sepolicy.cil', 'system_ext_sepolicy.cil', 'product_sepolicy.cil'}:
        continue
    data = path.read_bytes()
    if sha(data) != item['sha256']:
        raise ValueError('Current input changed')
    inputs.append(item)
    text = data.decode()
    for kind, start, stop in port.statements(text, cil.tokens):
        if kind in {'type', 'typeattribute'}:
            name = cil.tokens(text[start:stop])[2][1]
            (types if kind == 'type' else attrs).add(name)
platform_symbols = types | {name+'_30_0' for name in types}
text = original['vendor_sepolicy.cil'].decode()
forms = list(port.statements(text, cil.tokens))
pieces, end, ledger = [], 0, []
for kind, start, stop in forms:
    if kind != 'typeattributeset':
        continue
    ts = cil.tokens(text[start:stop])
    name = ts[2][1]
    if name not in attrs:
        continue
    members = ts[4:-2]
    if ts[3][0] != '(' or ts[-2][0] != ')' or any(t[0] != 'symbol' or t[1] in {'and', 'or', 'not', 'xor', 'all'} for t in members):
        raise ValueError('Non-flat shared membership requires review: '+name)
    removed = [t[1] for t in members if t[1] in platform_symbols]
    if not removed:
        continue
    kept = [t[1] for t in members if t[1] not in platform_symbols]
    replacement = '(typeattributeset '+name+' ('+' '.join(kept)+'))' if kept else ''
    # Preserve line locations even when a whole assignment becomes redundant.
    replacement += '\n' * (text[start:stop].count('\n') - replacement.count('\n'))
    pieces.extend([text[end:start], replacement])
    end = stop
    ledger.append({'attribute': name, 'source_line': text.count('\n', 0, start)+1,
                   'removed_platform_symbols': removed, 'retained_members': kept,
                   'original_statement': text[start:stop], 'replacement_statement': replacement})
pieces.append(text[end:])
staged = ''.join(pieces)
def protected_rules(data):
    return [data[s:e] for k, s, e in port.statements(data, cil.tokens) if k != 'typeattributeset']
if protected_rules(staged) != protected_rules(text) or cil.rule_counts(text) != cil.rule_counts(staged):
    raise ValueError('AV rules/assertions/non-membership statements changed')
output.mkdir(parents=True)
dest = output/'vendor/etc/selinux'
dest.mkdir(parents=True)
for name, data in original.items():
    (dest/name).write_bytes(staged.encode() if name == 'vendor_sepolicy.cil' else data)
if (source/'genfs_labels_version.txt').exists():
    (dest/'genfs_labels_version.txt').write_bytes((source/'genfs_labels_version.txt').read_bytes())
(output/'membership-port-ledger.json').write_text(json.dumps(ledger, indent=2)+'\n')
report = {'scope': __doc__, 'current_inputs': inputs,
          'changed_shared_attribute_assignments': len(ledger),
          'removed_platform_symbol_occurrences': sum(len(x['removed_platform_symbols']) for x in ledger),
          'vendor_rules_before': cil.rule_counts(text), 'vendor_rules_after': cil.rule_counts(staged),
          'all_non_membership_statements_byte_exact': True,
          'all_vendor_private_and_legacy_only_members_preserved': True,
          'runtime_validated': False, 'security_approved': False, 'flash_ready': False,
          'runner_sha256': sha(Path(__file__).read_bytes()),
          'inputs': [{'name': n, 'sha256': sha(b), 'staged_sha256': sha((dest/n).read_bytes())}
                     for n, b in original.items()]}
for name, data in original.items():
    if (source/name).read_bytes() != data:
        raise ValueError('Input changed during staging')
(output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
print('STAGED shared attribute assignments:', len(ledger))
