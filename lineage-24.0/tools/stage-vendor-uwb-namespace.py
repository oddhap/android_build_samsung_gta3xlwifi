#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage a checksum-bound alpha-rename of two Samsung private SELinux types.

Offline metadata experiment only, NOT a vendor image builder or security approval.
Never writes into Android TOP or the supplied preserved vendor tree. Public
versioned policy and all rules/neverallows stay byte-identical except private
symbol names in vendor_sepolicy.cil and one endpoint's context type.
"""
import argparse
from collections import Counter
import datetime
import difflib
import hashlib
import json
from pathlib import Path
import re

RENAMES = {'uwb_service': 'vendor_samsung_legacy_uwb_service',
           'hal_uwb_service': 'vendor_samsung_legacy_hal_uwb_service'}
ENDPOINT = 'vendor.samsung.hardware.uwb@1.0::ISehUwb/default'
FILES = ('vendor_sepolicy.cil', 'plat_pub_versioned.cil', 'plat_sepolicy_vers.txt',
         'vendor_service_contexts', 'vendor_hwservice_contexts', 'vendor_file_contexts',
         'vendor_property_contexts', 'vendor_seapp_contexts', 'vndservice_contexts')
RULES = {'allow', 'neverallow', 'allowx', 'neverallowx', 'allowxperm',
         'neverallowxperm', 'typepermissive'}
MAX_BYTES = 16 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tokens(text):
    """Return lossless token spans; never mistake string/comment text for symbols."""
    if '\0' in text:
        raise ValueError('NUL in text metadata')
    result, depth, i = [], 0, 0
    while i < len(text):
        c = text[i]
        if c.isspace():
            i += 1
        elif c == ';':
            end = text.find('\n', i)
            i = len(text) if end < 0 else end + 1
        elif c in '()':
            depth += 1 if c == '(' else -1
            if depth < 0:
                raise ValueError('Unbalanced CIL parentheses')
            result.append((c, c, i, i + 1))
            i += 1
        elif c == '"':
            start = i
            i += 1
            while i < len(text):
                if text[i] == '\\':
                    i += 2
                elif text[i] == '"':
                    i += 1
                    result.append(('string', text[start:i], start, i))
                    break
                else:
                    i += 1
            else:
                raise ValueError('Unterminated CIL string')
        else:
            start = i
            while i < len(text) and not text[i].isspace() and text[i] not in '();"':
                i += 1
            result.append(('symbol', text[start:i], start, i))
    if depth:
        raise ValueError('Unbalanced CIL parentheses')
    return result


def rewrite_cil(text, mapping):
    ts = tokens(text)
    pieces, end, counts = [], 0, Counter()
    for kind, value, start, stop in ts:
        if kind != 'symbol' or value not in mapping:
            continue
        pieces += [text[end:start], mapping[value]]
        end = stop
        counts[value] += 1
    pieces.append(text[end:])
    return ''.join(pieces), dict(counts)


def rule_counts(text):
    ts = tokens(text)
    return dict(Counter(ts[i + 1][1] for i in range(len(ts) - 1)
                        if ts[i][0] == '(' and ts[i + 1][0] == 'symbol'
                        and ts[i + 1][1] in RULES))


def stage(top, vendor, output, expected):
    top, vendor, output = top.resolve(), vendor.resolve(), output.resolve()
    if output.is_relative_to(top) or output.is_relative_to(vendor):
        raise ValueError('Output must stay outside protected TOP/vendor trees')
    if output.exists():
        raise FileExistsError('Refusing existing output')
    if not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('Expected policy checksum must be a SHA-256 hex digest')
    if (vendor/'odm/etc/selinux/odm_sepolicy.cil').exists():
        raise ValueError('Unreviewed ODM policy must not be silently omitted from this metadata-only experiment')
    src = vendor/'etc/selinux'
    names = list(FILES)
    if (src/'genfs_labels_version.txt').exists():
        names.append('genfs_labels_version.txt')
    originals = {}
    for name in names:
        p = src/name
        if p.is_symlink() or not p.resolve().is_relative_to(vendor):
            raise ValueError('Symlink/alias input refused: ' + name)
        if not p.is_file():
            raise ValueError('Required metadata is not a regular file: ' + name)
        if p.stat().st_size > MAX_BYTES:
            raise ValueError('Oversized metadata: ' + name)
        data = p.read_bytes()
        if b'\0' in data:
            raise ValueError('Binary/NUL metadata refused: ' + name)
        data.decode('utf-8')
        originals[name] = data
    if sha(originals['vendor_sepolicy.cil']) != expected:
        raise ValueError('Vendor policy checksum mismatch')
    if originals['plat_sepolicy_vers.txt'] != b'30.0\n':
        raise ValueError('Only the reviewed version-30 vendor input is supported')
    cil = originals['vendor_sepolicy.cil'].decode()
    ts = tokens(cil)
    if any(t[0] == 'string' and t[1] in {'"' + n + '"' for n in RENAMES} for t in ts):
        raise ValueError('Quoted private identifier needs explicit semantic review')
    symbols = Counter(t[1] for t in ts if t[0] == 'symbol')
    for old, new in RENAMES.items():
        decls = sum(1 for i in range(len(ts) - 3)
                    if [x[:2] for x in ts[i:i + 4]] ==
                    [('(', '('), ('symbol', 'type'), ('symbol', old), (')', ')')])
        if decls != 1 or symbols[new]:
            raise ValueError('Expected unique private declaration and unused destination: ' + old)
    public = tokens(originals['plat_pub_versioned.cil'].decode())
    public_forbidden = set(RENAMES) | set(RENAMES.values())
    if any(t[0] == 'symbol' and t[1] in public_forbidden for t in public):
        raise ValueError('Private source/destination overlaps a versioned public policy symbol')
    newcil, occurrences = rewrite_cil(cil, RENAMES)
    inverse, _ = rewrite_cil(newcil, {v: k for k, v in RENAMES.items()})
    if inverse != cil or rule_counts(cil) != rule_counts(newcil):
        raise ValueError('Alpha-rename roundtrip/rule invariant failed')
    staged = dict(originals)
    staged['vendor_sepolicy.cil'] = newcil.encode()
    context = originals['vendor_service_contexts'].decode()
    matches = []
    for line in context.splitlines():
        content = line.split('#', 1)[0].split()
        if content and content[0] == ENDPOINT:
            matches.append(content)
    if matches != [[ENDPOINT, 'u:object_r:hal_uwb_service:s0']]:
        raise ValueError('Expected exactly the reviewed Samsung endpoint and original label')
    label = 'u:object_r:hal_uwb_service:s0'
    replacement = 'u:object_r:' + RENAMES['hal_uwb_service'] + ':s0'
    # Only actual context fields, not comments, are modified.
    lines = []
    for line in context.splitlines(keepends=True):
        content, sep, comment = line.partition('#')
        if content.split()[:1] == [ENDPOINT]:
            content = content.replace(label, replacement)
        lines.append(content + sep + comment)
    staged['vendor_service_contexts'] = ''.join(lines).encode()
    if staged['vendor_service_contexts'].decode().replace(replacement, label) != context:
        raise ValueError('Context roundtrip failed')
    # Any unreviewed context/reference would require a new explicit migration.
    pattern = re.compile(r'(?<![A-Za-z0-9_])(uwb_service|hal_uwb_service)(?![A-Za-z0-9_])')
    for name, data in staged.items():
        if name.endswith('contexts'):
            if any(pattern.search(line.split('#', 1)[0]) for line in data.decode().splitlines()):
                raise ValueError('Unmigrated private context in ' + name)
    changed = sorted(n for n in names if originals[n] != staged[n])
    if changed != ['vendor_sepolicy.cil', 'vendor_service_contexts']:
        raise ValueError('Unexpected changed metadata set')
    # Create only after all validation; never copy compiled policy, hashes or sk.
    output.mkdir(parents=True, exist_ok=False)
    dest = output/'vendor/etc/selinux'
    dest.mkdir(parents=True)
    for name, data in staged.items():
        (dest/name).write_bytes(data)
    patch = ''.join(''.join(difflib.unified_diff(originals[n].decode().splitlines(True),
                        staged[n].decode().splitlines(True), fromfile='a/etc/selinux/' + n,
                        tofile='b/etc/selinux/' + n)) for n in changed)
    (output/'metadata.patch').write_text(patch)
    # Check sources once more; no original input writes occurred.
    if any((src/n).read_bytes() != v for n, v in originals.items()):
        raise ValueError('Input changed during staging; do not use this output')
    report = {'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'status': 'STAGED_METADATA_ONLY_NOT_A_VENDOR_IMAGE_NOT_SECURITY_APPROVED',
              'renames': RENAMES, 'source_vendor': str(vendor), 'changed_files': changed,
              'symbol_occurrences': occurrences, 'rule_counts_before': rule_counts(cil),
              'rule_counts_after': rule_counts(newcil), 'byte_exact_inverse_verified': True,
              'endpoint': ENDPOINT, 'full_vendor_tree_or_precompiled_policy_copied': False,
              'vendor_image_validation_performed_by_this_tool': False,
              'original_sources_images_or_device_modified': False,
              'hardware_tested': False, 'security_approved': False, 'flash_ready': False,
              'inputs': [{'name': n, 'sha256': sha(v), 'staged_sha256': sha(staged[n])}
                         for n, v in originals.items()], 'metadata_patch_sha256': sha(patch.encode())}
    (output/'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--top', type=Path, required=True)
    p.add_argument('--vendor', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--expected-policy-sha256', required=True)
    args = p.parse_args()
    r = stage(args.top, args.vendor, args.output, args.expected_policy_sha256)
    print('STAGED ONLY:', ', '.join(r['changed_files']), '; original rules and inputs preserved')


if __name__ == '__main__':
    main()
