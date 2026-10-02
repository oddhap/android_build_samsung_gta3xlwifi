#!/usr/bin/env python3
"""Check the built framework against actual stock vendor and built kernel.

Run after system VINTF matrices have been produced. This is independent of
target-files' generated vendor metadata, which can differ from the vendor image.
"""
import json
import subprocess
from pathlib import Path

root = Path('/srv/android')
top = root / 'src/lineage-21.0'
out = top / 'out/target/product/gta3xlwifi'
artifacts = root / 'artifacts/lineage-21/native-vintf-check'
artifacts.mkdir(parents=True, exist_ok=True)
empty = artifacts / 'empty-odm'
empty.mkdir(exist_ok=True)
system = out / 'system'
required = ['manifest.xml', 'compatibility_matrix.device.xml']
required += [f'compatibility_matrix.{level}.xml' for level in ('3', '5', '6', '7', '8')]
missing = [name for name in required if not (system / 'etc/vintf' / name).exists()]
if missing:
    raise SystemExit(f'Framework metadata is not fully built yet: {", ".join(missing)}')
command = [str(top / 'out/host/linux-x86/bin/checkvintf'), '--check-compat']
for partition, path in (
    ('system', system), ('system_ext', system / 'system_ext'),
    ('product', out / 'product'), ('vendor', root / 'vendor-stock/extracted/vendor'),
    ('odm', empty),
):
    command += ['--dirmap', f'/{partition}:{path}']
command += ['--property', 'ro.product.first_api_level=28',
            '--property', 'ro.boot.product.hardware.sku=',
            '--property', 'ro.boot.product.vendor.sku=',
            '--kernel', f'4.4.302:{root}/artifacts/kernel-smoke/config']
result = subprocess.run(command, capture_output=True, text=True)
(artifacts / 'checkvintf.log').write_text(result.stdout + result.stderr)
(artifacts / 'report.json').write_text(json.dumps({
    'device': 'SM-T510', 'exit_code': result.returncode, 'command': command,
    'framework_kernel_profile': 'SM-T510 legacy iptables/qtaguid; five networking requirements adapted',
    'unmodified_upstream_kernel_profile_passed': False,
    'actual_stock_vendor_used': True, 'kernel_config_checked': True,
    'hardware_tested': False,
}, indent=2) + '\n')
print(result.stdout, end='')
print('\n'.join(result.stderr.splitlines()[-16:]))
print(f'Native VINTF compatibility exit code: {result.returncode}')
raise SystemExit(result.returncode)
