#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Link built 23.2 policy with an explicitly supplied extracted vendor.

Strict neverallow checking is mandatory. --runtime-diagnostic additionally
repeats init's -N compilation; it never turns a strict failure into a pass.
This tool changes no source, image, kernel or device enforcement setting.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda: f.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--top', type=Path, required=True)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--out-dir', default='out',
                        help='Relative isolated build output beneath TOP (default: out)')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runtime-diagnostic', action='store_true')
    args = parser.parse_args()
    top, vendor, output = args.top.resolve(), args.vendor.resolve(), args.output.resolve()
    relative_out = Path(args.out_dir)
    if (not args.out_dir or relative_out.is_absolute() or
            any(part in ('.', '..') for part in args.out_dir.split('/'))):
        raise ValueError('Build output must be a nonempty relative path without dot components')
    build_out = (top / relative_out).resolve()
    if build_out == top or not build_out.is_relative_to(top):
        raise ValueError('Resolved build output must stay beneath TOP')
    if output.is_relative_to(top) or output.is_relative_to(vendor):
        raise ValueError('Report/output must stay outside protected source and vendor trees')
    out = build_out / 'target/product/gta3xlwifi'
    vpolicy = vendor / 'etc/selinux'
    version = (vpolicy / 'plat_sepolicy_vers.txt').read_text().strip()
    if not re.fullmatch(r'\d+\.\d+', version):
        raise ValueError('Invalid vendor policy version')
    system = out / 'system/etc/selinux'
    ext = out / 'system/system_ext/etc/selinux'
    product = out / 'product/etc/selinux'
    inputs = [system / 'plat_sepolicy.cil', system / f'mapping/{version}.cil']
    for path in [system / f'mapping/{version}.compat.cil',
                 ext / 'system_ext_sepolicy.cil', ext / f'mapping/{version}.cil',
                 ext / f'mapping/{version}.compat.cil', product / 'product_sepolicy.cil',
                 product / f'mapping/{version}.cil']:
        if path.exists():
            inputs.append(path)
    inputs += [vpolicy / 'plat_pub_versioned.cil', vpolicy / 'vendor_sepolicy.cil']
    odm = vendor / 'odm/etc/selinux/odm_sepolicy.cil'
    if odm.exists():
        inputs.append(odm)
    genfs_version = 202404  # Actual libgenfslabelsversion default in this source lock.
    genfs_version_file = vpolicy / 'genfs_labels_version.txt'
    if genfs_version_file.exists():
        try:
            genfs_version = int(genfs_version_file.read_text().strip())
        except ValueError:
            pass
    genfs = system / f'plat_sepolicy_genfs_{genfs_version}.cil'
    if genfs.exists():
        inputs.append(genfs)
    for path in inputs:
        if not path.is_file():
            raise FileNotFoundError(f'Missing policy input: {path}')
    compiler = build_out / 'host/linux-x86/bin/secilc'
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for mode in ['strict'] + (['init-runtime-diagnostic'] if args.runtime_diagnostic else []):
        command = [str(compiler), '-m', '-M', 'true', '-G', '-c', '30',
                   '-o', str(output / f'{mode}.policy'), '-f', '/dev/null']
        if mode != 'strict':
            init_source = (top / 'system/core/init/selinux.cpp').read_text()
            if '"-m", "-M", "true", "-G", "-N"' not in init_source:
                raise ValueError('Current init flags differ; review runtime diagnostic manually')
            command.append('-N')
        command += [str(path) for path in inputs]
        result = subprocess.run(command, capture_output=True, text=True)
        (output / f'{mode}.log').write_text(result.stdout + result.stderr)
        entry = {'mode': mode, 'exit_code': result.returncode,
                 'neverallow_checks_enabled': mode == 'strict', 'command': command}
        if result.returncode == 0:
            entry['compiled_policy_sha256'] = sha256(output / f'{mode}.policy')
        results.append(entry)
        print(f'{mode}: exit {result.returncode}')
        print('\n'.join((result.stdout + result.stderr).splitlines()[:12]))
    report = {'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'passed_strict': results[0]['exit_code'] == 0,
              'build_output_root': str(build_out), 'compiler_sha256': sha256(compiler),
              'policy_binary_version': 30, 'vendor_policy_version': version,
              'vendor_genfs_version': genfs_version, 'genfs_fragment_present': genfs.exists(),
              'inputs': [{'path': str(path), 'sha256': sha256(path)} for path in inputs],
              'results': results, 'hardware_tested': False, 'source_or_device_modified': False,
              'runtime_diagnostic_does_not_override_strict_result': True}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['passed_strict'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
