#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare vendor-referenced attribute expressions, not effective memberships."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
for name in ['old', 'new', 'vendor', 'output']:
    p.add_argument('--'+name, type=Path, required=True)
a = p.parse_args()
if a.output.exists():
    raise FileExistsError(a.output)
spec = importlib.util.spec_from_file_location('cil', Path(__file__).with_name('stage-vendor-uwb-namespace.py'))
cil = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cil)


def definitions(path):
    ts = cil.tokens(path.read_text())
    depth, result = 0, {}
    for i, token in enumerate(ts):
        if token[0] == '(':
            if depth == 0:
                start = i
            depth += 1
        elif token[0] == ')':
            depth -= 1
            form = ts[start:i+1]
            if depth == 0 and form[1][1] == 'typeattributeset':
                name = form[2][1]
                result.setdefault(name, []).append([t[1] for t in form[3:-1]])
    return result


old, new = definitions(a.old), definitions(a.new)
used = {t[1] for t in cil.tokens(a.vendor.read_text()) if t[0] == 'symbol'}
common = sorted(old.keys() & new.keys() & used)
different = [{'name': n, 'old_expression_tokens': old[n], 'new_expression_tokens': new[n]}
             for n in common if old[n] != new[n]]
report = {'scope': __doc__, 'vendor_referenced_shared_attribute_definitions': len(common),
          'different_token_expressions': different,
          'compiler_generated_name_collisions': [x['name'] for x in different if x['name'].startswith('base_typeattr_')],
          'effective_membership_equivalence_tested': False,
          'inputs_sha256': {str(f): hashlib.sha256(f.read_bytes()).hexdigest()
                            for f in [a.old, a.new, a.vendor, Path(__file__)]}}
a.output.write_text(json.dumps(report, indent=2)+'\n')
print('Token-expression differences:', len(different), '; generated-name collisions:', report['compiler_generated_name_collisions'])
