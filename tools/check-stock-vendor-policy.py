#!/usr/bin/env python3
"""Link framework policy with actual stock vendor CIL, without fake vendor data.

Default mode checks cross-version neverallow assertions. --runtime-mode repeats
Android init's own compilation flags (including -N). That does not disable
SELinux enforcement; it omits compile-time assertions from old platform policy.
Neither mode demonstrates hardware operation or complete security equivalence.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--runtime-mode', action='store_true')
args = parser.parse_args()
mode = 'runtime' if args.runtime_mode else 'strict'
root = Path('/srv/android')
top = root / 'src/lineage-19.1'
out = top / 'out/target/product/gta3xlwifi'
vendor = root / 'vendor-stock/extracted/vendor/etc/selinux'
artifacts = root / 'artifacts/stock-vendor-policy-check'
artifacts.mkdir(parents=True, exist_ok=True)

version = (vendor / 'plat_sepolicy_vers.txt').read_text().strip()
mapping = out / f'system/etc/selinux/mapping/{version}.cil'
if not mapping.exists():
    candidates = list((top / f'out/soong/.intermediates/system/sepolicy/plat_{version}.cil').rglob(f'plat_{version}.cil'))
    if len(candidates) != 1:
        raise SystemExit(f'Build plat_{version}.cil first; found {len(candidates)} mapping candidates')
    mapping = candidates[0]

inputs = [out / 'system/etc/selinux/plat_sepolicy.cil', mapping]
for path in (
    out / f'system/etc/selinux/mapping/{version}.compat.cil',
    out / 'system/system_ext/etc/selinux/system_ext_sepolicy.cil',
    out / f'system/system_ext/etc/selinux/mapping/{version}.cil',
    out / f'system/system_ext/etc/selinux/mapping/{version}.compat.cil',
    out / 'product/etc/selinux/product_sepolicy.cil',
    out / f'product/etc/selinux/mapping/{version}.cil',
):
    if path.exists():
        inputs.append(path)
inputs += [vendor / 'plat_pub_versioned.cil', vendor / 'vendor_sepolicy.cil']
for path in inputs:
    if not path.exists():
        raise SystemExit(f'Missing policy input: {path}')
command = [str(top / 'out/host/linux-x86/bin/secilc'), '-m', '-M', 'true', '-G', '-c', '30',
           '-o', str(artifacts / f'{mode}-combined-sepolicy'), '-f', '/dev/null']
if args.runtime_mode:
    command.append('-N')
command += [str(p) for p in inputs]
result = subprocess.run(command, capture_output=True, text=True)
(artifacts / f'{mode}-compiler.log').write_text(result.stdout + result.stderr)
report = {
    'device': 'SM-T510', 'stock_vendor_policy_version': version,
    'mode': mode, 'neverallow_checks_enabled': not args.runtime_mode, 'exit_code': result.returncode,
    'command': command,
    'inputs': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in inputs],
    'hardware_tested': False,
}
(artifacts / f'{mode}-report.json').write_text(json.dumps(report, indent=2) + '\n')
lines = (result.stdout + result.stderr).splitlines()
print('\n'.join(lines[:12]))
if len(lines) > 12:
    print(f'Full compiler output ({len(lines)} lines) saved under {artifacts}')
print(f'Stock vendor policy {mode} link exit code: {result.returncode}')
raise SystemExit(result.returncode)
