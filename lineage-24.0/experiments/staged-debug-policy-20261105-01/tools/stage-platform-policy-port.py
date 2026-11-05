#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Isolate the legacy public symbol ABI from superseded platform behavior.

Owner decision 2026-11-05: retain Android17 and Samsung vendor assertions;
port the old platform component. This stages only an offline metadata proposal.
Current platform CIL supplies platform behavior and assertions unchanged. Legacy
symbol identities remain; optional attribute rebasing is explicitly recorded.
No allow statement is added. No -N compilation or effective-permission approval.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path

DECLARATIONS = {'type', 'typeattribute', 'typeattributeset',
                'expandtypeattribute', 'roletype'}
BEHAVIOR = {'allow', 'allowx', 'neverallow', 'neverallowx', 'dontaudit', 'auditallow'}
EXPECTED = {'allow': 4461, 'typeattribute': 1933, 'neverallow': 1657,
            'roletype': 1111, 'type': 1110, 'typeattributeset': 641,
            'expandtypeattribute': 195, 'neverallowx': 168, 'allowx': 137,
            'dontaudit': 67, 'auditallow': 1}


def statements(text, tokenizer):
    ts = tokenizer(text)
    depth = 0
    for i, token in enumerate(ts):
        if token[0] == '(':
            if depth == 0:
                start, kind = token[2], ts[i + 1][1]
            depth += 1
        elif token[0] == ')':
            depth -= 1
            if depth == 0:
                yield kind, start, token[3]
        elif depth == 0:
            raise ValueError('Unexpected top-level CIL token')


def stage(top, vendor, output, current_report=None):
    spec = importlib.util.spec_from_file_location('cil', Path(__file__).with_name('stage-vendor-uwb-namespace.py'))
    cil = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cil)
    top, vendor, output = top.resolve(), vendor.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(top) or output.is_relative_to(vendor):
        raise ValueError('Output must be new and outside preserved input trees')
    sha = lambda data: hashlib.sha256(data).hexdigest()
    original = {name: (vendor/'etc/selinux'/name).read_bytes() for name in cil.FILES}
    if sha(original['plat_pub_versioned.cil']) != '4dd55346c46e6d374c5fee79e1caeb1f971a4dc048cd96bedadfb676e0ec11c4':
        raise ValueError('Unreviewed legacy public policy')
    if sha(original['vendor_sepolicy.cil']) != '18d979058fcffc42b06ccea8fd60b81dd506e8b06adb17804c72d277aa52b227':
        raise ValueError('Expected reviewed namespace/capability-tightening parent')
    if (vendor/'odm/etc/selinux/odm_sepolicy.cil').exists():
        raise ValueError('Unreviewed ODM policy')
    text = original['plat_pub_versioned.cil'].decode()
    forms = list(statements(text, cil.tokens))
    if dict(Counter(kind for kind, _, _ in forms)) != EXPECTED:
        raise ValueError('Unexpected legacy statement inventory')
    shared_attributes, current_inputs = set(), []
    if current_report:
        baseline = json.loads(current_report.read_text())
        for item in baseline['inputs']:
            path = Path(item['path'])
            if path.name not in {'plat_sepolicy.cil', 'system_ext_sepolicy.cil', 'product_sepolicy.cil'}:
                continue
            data = path.read_bytes()
            if sha(data) != item['sha256']:
                raise ValueError('Current policy input changed: '+str(path))
            current_inputs.append(item)
            current_text = data.decode()
            for kind, start, stop in statements(current_text, cil.tokens):
                if kind == 'typeattribute':
                    shared_attributes.add(cil.tokens(current_text[start:stop])[2][1])
        if not current_inputs:
            raise ValueError('No reviewed current platform inputs')
    pieces, end, ledger, retained = [], 0, [], []
    for kind, start, stop in forms:
        form = text[start:stop]
        modern_membership = (kind == 'typeattributeset' and
                             cil.tokens(form)[2][1] in shared_attributes)
        modern_expansion = (kind == 'expandtypeattribute' and
                            any(t[0] == 'symbol' and t[1] in shared_attributes
                                for t in cil.tokens(form)[2:]))
        if kind in DECLARATIONS and not (modern_membership or modern_expansion):
            retained.append(form)
            continue
        if kind not in BEHAVIOR and not (modern_membership or modern_expansion):
            raise ValueError('Unreviewed behavioral form: ' + kind)
        pieces.append(text[end:start])
        # Retain source line locations for diagnostics/review.
        removed = text[start:stop]
        pieces.append(''.join('\n' if c == '\n' else ' ' for c in removed))
        end = stop
        ledger.append({'kind': kind, 'reason': 'current_platform_attribute_owns_membership_or_expansion' if modern_membership or modern_expansion else 'current_platform_owns_behavior',
                       'line': text.count('\n', 0, start) + 1,
                       'sha256': sha(removed.encode()), 'statement': removed})
    pieces.append(text[end:])
    staged = ''.join(pieces)
    if [staged[s:e] for _, s, e in statements(staged, cil.tokens)] != retained:
        raise ValueError('Legacy symbol/attribute definitions changed')
    output.mkdir(parents=True)
    dest = output/'vendor/etc/selinux'
    dest.mkdir(parents=True)
    for name, data in original.items():
        (dest/name).write_bytes(staged.encode() if name == 'plat_pub_versioned.cil' else data)
    if (vendor/'etc/selinux/genfs_labels_version.txt').exists():
        data = (vendor/'etc/selinux/genfs_labels_version.txt').read_bytes()
        (dest/'genfs_labels_version.txt').write_bytes(data)
    (output/'superseded-platform-behavior.json').write_text(json.dumps(ledger, indent=2)+'\n')
    report = {'scope': __doc__, 'legacy_statement_counts': EXPECTED,
              'retained_statement_counts': dict(Counter(k for k, _, _ in statements(staged, cil.tokens))),
              'superseded_platform_statement_counts': dict(Counter(x['kind'] for x in ledger)),
              'vendor_policy_byte_identical_to_reviewed_parent': True,
              'vendor_assertions_retained': cil.rule_counts(original['vendor_sepolicy.cil'].decode()),
              'retained_statements_byte_exact': True,
              'legacy_declarations_and_attribute_expressions_byte_exact': not bool(current_report),
              'current_attribute_rebase_enabled': bool(current_report),
              'current_inputs': current_inputs,
              'vendor_referenced_versioned_and_compiler_private_attribute_definitions_retained': True,
              'allow_statements_added': False, 'current_platform_inputs_modified': False,
              'original_images_modified': False, 'security_approved': False, 'flash_ready': False,
              'runner_sha256': sha(Path(__file__).read_bytes()),
              'inputs': [{'name': n, 'sha256': sha(b), 'staged_sha256': sha((dest/n).read_bytes())}
                         for n, b in original.items()]}
    for name, data in original.items():
        if (vendor/'etc/selinux'/name).read_bytes() != data:
            raise ValueError('Input changed during staging')
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print('STAGED: legacy symbol ABI retained; platform behavior supplied by current Android17 CIL')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for n in ['top', 'vendor', 'output']:
        p.add_argument('--'+n, type=Path, required=True)
    p.add_argument('--current-platform-report', type=Path,
                   help='Use current membership/expansion for attributes declared by Android17')
    a = p.parse_args()
    stage(a.top, a.vendor, a.output, a.current_platform_report)
