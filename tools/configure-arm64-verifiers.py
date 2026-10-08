#!/usr/bin/env python3
"""Retarget isolated verifiers to declared ARM64 inputs, preserving checks."""
import json
from pathlib import Path

ROOT = Path('/srv/android')
PORT = ROOT/'ports/lineage-21-arm64/lineage-21'
OUT = ROOT/'artifacts/lineage-21-arm64'
vendor_sha = json.loads((OUT/'vendor-image-report.json').read_text())['sparse_sha256']
names = ('verify-port-package.py', 'verify-native-images.py', 'verify-native-layout.py',
         'verify-release.py', 'verify-usage-compat.py', 'check-native-vintf.py', 'check-stock-vendor-policy.py')
for name in names:
    path = PORT/'tools'/name
    text = path.read_text()
    text = text.replace("'src/lineage-21.0'", "'src/lineage-21.0-arm64'")
    text = text.replace("'/srv/android/src/lineage-21.0'", "'/srv/android/src/lineage-21.0-arm64'")
    text = text.replace("'src/lineage-21.0/out/target/product/gta3xlwifi'", "'src/lineage-21.0-arm64/out/target/product/gta3xlwifi'")
    text = text.replace("'artifacts/lineage-21'", "'artifacts/lineage-21-arm64'")
    text = text.replace("'artifacts/lineage-21/native-image-check.json'", "'artifacts/lineage-21-arm64/native-image-check.json'")
    text = text.replace("'artifacts/lineage-21/stock-vendor-policy-check'", "'artifacts/lineage-21-arm64/hybrid-vendor-policy-check'")
    text = text.replace("'/srv/android/artifacts/lineage-21/release'", "'/srv/android/artifacts/lineage-21-arm64/release'")
    text = text.replace('artifacts/lineage-21/', 'artifacts/lineage-21-arm64/')
    if name == 'verify-native-images.py':
        text = text.replace("'logs/lineage21-rom-build-final.exit'", "'logs/lineage-21-arm64/full-build.exit'")
        text = text.replace('4cc684231b4a1c355169cea61b4ea5196401bc5f68c7f74a32c1ec290abc0006', vendor_sha)
        text = text.replace('verified stock image', 'reviewed hybrid vendor image')
    if name in ('verify-port-package.py', 'verify-native-layout.py'):
        text = text.replace("b'\\x7fELF\\x01'", "b'\\x7fELF\\x02'")
        text = text.replace("b'\\x28\\x00'", "b'\\xb7\\x00'")
        text = text.replace('ARM32 ELF', 'ARM64 ELF')
        text = text.replace('SYSTEM/lib/', 'SYSTEM/lib64/')
        text = text.replace('/system/lib/', '/system/lib64/')
        text = text.replace("'system/lib'", "'system/lib64'")
        text = text.replace("'system/lib/", "'system/lib64/")
    if name == 'verify-native-layout.py':
        text = text.replace('src/kernel-gta3xlwifi/fs/ext4/ext4.h',
                            'github-upload-lineage21/android_kernel_samsung_gta3xlwifi/fs/ext4/ext4.h')
    if name == 'verify-port-package.py':
        text = text.replace("'gta3xlwifi-meminfo-probe'))", "'gta3xlwifi-meminfo-probe', 'gta3xlwifi_abi_probe'))")
        text = text.replace("{'system', 'product', 'boot'}", "{'system', 'product', 'boot', 'vendor'}")
    if name == 'verify-release.py':
        text = text.replace('SYSTEM/lib/', 'SYSTEM/lib64/')
        text = text.replace("'-privatekeys.zip'", "'-arm64-privatekeys.zip'")
        text = text.replace("{'system', 'product', 'boot'}", "{'system', 'product', 'boot', 'vendor'}")
        text = text.replace("('boot.img',33554432)]", "('boot.img',33554432), ('vendor.img',343932928), ('dtbo.img',8388608)]")
        if 'vendor_unmounted_guard_before_writes' not in text:
            text = text.replace('import gzip\n', 'import gzip\nimport ast\n')
            text = text.replace("        checks['updater_static_arm64'] = True", '''        guard = archive.read('vendor-unmounted-check.sh')
        source = Path('/srv/android/src/lineage-21.0-arm64/device/samsung/gta3xlwifi/releasetools.py')
        definitions = [node for node in ast.parse(source.read_text()).body
                       if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                       and target.id == '_VENDOR_MOUNT_GUARD' for target in node.targets)]
        assert len(definitions) == 1 and guard == ast.literal_eval(definitions[0].value)
        assert b'/proc/mounts' in guard
        assert script.index('run_program("/sbin/sh", "/tmp/vendor-unmounted-check.sh")') < script.index('block_image_update(')
        checks['vendor_unmounted_guard_before_writes'] = True
        checks['vendor_unmounted_guard_sha256'] = hashlib.sha256(guard).hexdigest()
        checks['updater_static_arm64'] = True''')
        if 'updater_static_arm64' not in text:
            text = text.replace('import gzip\n', 'import gzip\nimport io\nfrom elftools.elf.elffile import ELFFile\n')
            text = text.replace("        helper = archive.read('recovery-header-sync')", '''        updater = archive.read('META-INF/com/google/android/update-binary')
        assert updater[:5] == b'\\x7fELF\\x02' and struct.unpack_from('<H', updater, 18)[0] == 183
        updater_elf = ELFFile(io.BytesIO(updater))
        for segment in updater_elf.iter_segments():
            assert segment['p_type'] != 'PT_INTERP', 'Updater requires a missing ARM64 recovery linker'
            if segment['p_type'] == 'PT_DYNAMIC':
                assert all(tag.entry.d_tag != 'DT_NEEDED' for tag in segment.iter_tags())
        checks['updater_static_arm64'] = True
        checks['updater_sha256'] = hashlib.sha256(updater).hexdigest()
        helper = archive.read('recovery-header-sync')''')
    if name in ('check-native-vintf.py', 'check-stock-vendor-policy.py'):
        text = text.replace('vendor-stock/extracted/vendor', 'artifacts/lineage-21-arm64/vendor-hybrid-mount')
        text = text.replace("'actual_stock_vendor_used'", "'actual_hybrid_vendor_used'")
        text = text.replace('artifacts/kernel-smoke/config', 'artifacts/lineage-21-arm64/baseline-inputs/kernel.config')
    path.write_text(text)
lock = PORT/'notes/source-inputs.lock.json'
data = json.loads(lock.read_text())
inputs = data['inputs']
inputs['baseline_arm32_vendor_sha256'] = '4cc684231b4a1c355169cea61b4ea5196401bc5f68c7f74a32c1ec290abc0006'
inputs['vendor_sha256'] = vendor_sha
inputs['vendor_unchanged_from_stock'] = False
inputs['hybrid_vendor_report'] = str(OUT/'vendor-image-report.json')
inputs['android14_hardware_tested'] = False
if 'android14_tested_rom_sha256' in inputs:
    inputs['baseline_arm32_tested_rom_sha256'] = inputs.pop('android14_tested_rom_sha256')
inputs['arm64_hardware_tested'] = False
lock.write_text(json.dumps(data, indent=2)+'\n')
print('Retargeted verifier paths, primary ELF class, exact vendor hash, and vendor OTA allowance; other checks retained.')
