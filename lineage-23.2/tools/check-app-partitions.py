#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check real app relocation and unchanged signing metadata; never reads keys.
Usage: check-app-partitions.py --top TOP --saved ARCHIVE --output NEW_JSON [--verify-apks]
Not an image-size, ROM security, OTA or hardware approval.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import shlex
import subprocess

APPS = ('webview', 'Backgrounds', 'PhotoTable')
PREFIX = 'lineage_gta3xlwifi-apkcerts-'


def records(text):
    result = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        entry = {}
        for token in shlex.split(line):
            key, value = token.split('=', 1)
            if key in entry:
                raise ValueError('Duplicate field in APK metadata: ' + key)
            entry[key] = value
        if not {'name', 'certificate', 'private_key', 'partition'} <= entry.keys():
            raise ValueError('Incomplete APK certificate metadata')
        result.append(entry)
    if not result:
        raise ValueError('Empty APK metadata is not a validation pass')
    return result


def canonical(entries):
    return Counter(tuple(sorted(entry.items())) for entry in entries)


def validate_metadata(before_text, after_text, doublecheck_text):
    before, after, doublecheck = map(records, (before_text, after_text, doublecheck_text))
    if canonical(after) != canonical(doublecheck):
        raise ValueError('Make/Soong APK metadata still disagree')
    expected = []
    counts = Counter()
    selected = {app + '.apk' for app in APPS}
    for original in before:
        entry = original.copy()
        if entry['name'] in selected:
            if entry['partition'] != 'product':
                raise ValueError('Baseline selected app was not on product')
            entry['partition'] = 'system'
            counts[entry['name']] += 1
        expected.append(entry)
    if set(counts) != selected or any(counts[name] != 1 for name in selected):
        raise ValueError('Missing or ambiguous selected app metadata')
    if canonical(expected) != canonical(after):
        raise ValueError('Unexpected metadata/signing change outside the three partition fields')
    return {'records_checked': len(after), 'signing_metadata_unchanged': True,
            'only_partition_fields_changed': list(APPS), 'make_soong_agree': True}


def cert_digests(tool, apk, top):
    result = subprocess.run([str(tool), 'verify', '--print-certs', str(apk)], cwd=top,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
    if result.returncode:
        raise ValueError('APK signature verification failed: ' + str(apk) + '\n' + result.stdout)
    digests = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$',
                         result.stdout, re.M)
    if not digests:
        raise ValueError('No verified signing-certificate digest: ' + str(apk))
    return sorted(value.lower() for value in digests)


def check(top, saved, verify_apks):
    product = top / 'out/target/product/gta3xlwifi'
    metadata = product / 'obj/PACKAGING/apkcerts_intermediates'
    report = validate_metadata(
        (saved / 'before-soong-apkcerts.txt').read_text(),
        (metadata / (PREFIX + 'soong_apkcerts_file_with_soong_and_make_modules_removed.txt')).read_text(),
        (metadata / (PREFIX + 'soong-doublecheck.txt')).read_text())
    report['apps'] = []
    for app in APPS:
        apk = product / 'system/app' / app / (app + '.apk')
        if not apk.is_file():
            raise ValueError('Missing real system APK: ' + str(apk))
        if list((product / 'product').rglob(app + '.apk')):
            raise ValueError('Duplicate/stale product APK: ' + app)
        entry = {'app': app, 'path': str(apk), 'bytes': apk.stat().st_size}
        if verify_apks:
            tool = top / 'out/host/linux-x86/bin/apksigner'
            before = cert_digests(tool, saved / app / (app + '.apk'), top)
            after = cert_digests(tool, apk, top)
            if before != after:
                raise ValueError('Actual signing certificate changed: ' + app)
            entry['verified_certificate_sha256'] = after
        report['apps'].append(entry)
    report.update(passed=True, actual_apk_signatures_checked=verify_apks,
                  private_signing_keys_read=False, tablet_accessed=False,
                  scope='APK layout and signing consistency only; not ROM readiness')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--top', type=Path, required=True)
    parser.add_argument('--saved', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verify-apks', action='store_true')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output must be a new file')
    try:
        report = check(args.top.resolve(), args.saved.resolve(), args.verify_apks)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report = {'passed': False, 'error': str(error), 'tablet_accessed': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
