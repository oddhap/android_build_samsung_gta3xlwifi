#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check built LineageOS 24 framework metadata against extracted SM-T510 vendor.

No HAL/kernel requirements are edited or ignored. This is a metadata-only
check, not proof that all framework HALs have been built or run on hardware.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
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
    parser.add_argument('--kernel-config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    top, vendor = args.top.resolve(), args.vendor.resolve()
    output, kernel = args.output.resolve(), args.kernel_config.resolve()
    out = top / 'out/target/product/gta3xlwifi'
    framework = out / 'system/etc/vintf'
    levels = ('3', '7', '8', '202404', '202504', '202604', 'device')
    required = [framework / 'manifest.xml']
    required += [framework / f'compatibility_matrix.{level}.xml' for level in levels]
    required += [vendor / 'etc/vintf/manifest.xml', vendor / 'etc/vintf/compatibility_matrix.xml', kernel]
    for path in required:
        if not path.is_file():
            raise FileNotFoundError(f'Missing input (build metadata first): {path}')
    output.mkdir(parents=True, exist_ok=False)
    empty_odm = output / 'empty-odm'
    empty_odm.mkdir()
    partitions = {'system': out / 'system', 'system_ext': out / 'system/system_ext',
                  'product': out / 'product', 'vendor': vendor, 'odm': empty_odm,
                  'apex': out / 'apex'}
    command = [str(top / 'out/host/linux-x86/bin/checkvintf'), '--check-compat']
    for name, path in partitions.items():
        command += ['--dirmap', f'/{name}:{path}']
    command += ['--property', 'ro.product.first_api_level=28',
                '--property', 'ro.boot.product.hardware.sku=',
                '--property', 'ro.boot.product.vendor.sku=',
                '--kernel', f'4.4.302:{kernel}']
    result = subprocess.run(command, capture_output=True, text=True)
    log = result.stdout + result.stderr
    (output / 'checkvintf.log').write_text(log)
    inputs = {kernel}
    for path in partitions.values():
        inputs.update(p for p in (path / 'etc/vintf').rglob('*') if p.is_file())
    apex_info = out / 'apex/apex-info-list.xml'
    if apex_info.is_file():
        inputs.add(apex_info)
    inputs.update(p for p in (out / 'apex').rglob('*.xml') if p.is_file())
    report = {'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'exit_code': result.returncode, 'passed': result.returncode == 0,
              'command': command, 'kernel_version': '4.4.302',
              'inputs': [{'path': str(p), 'sha256': sha256(p)} for p in sorted(inputs)],
              'odm': 'No separate ODM partition on this product; empty mapping',
              'scope': 'Currently built framework metadata only; not a complete ROM or runtime test',
              'activated_apex_inventory_present': apex_info.is_file(),
              'complete_post_apex_validation_proven': False,
              'framework_kernel_profile': 'Device-carried legacy FCM 3, inherited from the working 21 port',
              'unmodified_android17_runtime_kernel_requirements_proven': False,
              'kernel_requirements_ignored_or_edited_by_this_tool': False,
              'hardware_tested': False}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('\n'.join(log.splitlines()[-30:]))
    print(f'VINTF exit code: {result.returncode}')
    return 0 if result.returncode == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
