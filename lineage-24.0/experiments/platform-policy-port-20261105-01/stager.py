#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Isolate the legacy public symbol ABI from superseded platform behavior.

Owner decision 2026-11-05: retain Android17 and Samsung vendor assertions;
port the old platform component. This stages only an offline metadata proposal.
Current platform CIL supplies platform behavior and assertions unchanged. Legacy
declarations and attribute expressions stay byte-exact, including compiler-private
identities referenced by Samsung. No permission is added. No -N compilation.
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


def stage(top, vendor, output):
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
    pieces, end, ledger = [], 0, []
    for kind, start, stop in forms:
        if kind in DECLARATIONS:
            continue
        if kind not in BEHAVIOR:
            raise ValueError('Unreviewed behavioral form: ' + kind)
        pieces.append(text[end:start])
        # Retain source line locations for diagnostics/review.
        removed = text[start:stop]
        pieces.append(''.join('\n' if c == '\n' else ' ' for c in removed))
        end = stop
        ledger.append({'kind': kind, 'line': text.count('\n', 0, start) + 1,
                       'sha256': sha(removed.encode()), 'statement': removed})
    pieces.append(text[end:])
    staged = ''.join(pieces)
    retained = [text[s:e] for k, s, e in forms if k in DECLARATIONS]
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
              'retained_statement_counts': dict(Counter(k for k, _, _ in forms if k in DECLARATIONS)),
              'superseded_platform_statement_counts': dict(Counter(x['kind'] for x in ledger)),
              'vendor_policy_byte_identical_to_reviewed_parent': True,
              'vendor_assertions_retained': cil.rule_counts(original['vendor_sepolicy.cil'].decode()),
              'legacy_declarations_and_attribute_expressions_byte_exact': True,
              'permissions_added': False, 'current_platform_inputs_modified': False,
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
    a = p.parse_args()
    stage(a.top, a.vendor, a.output)
