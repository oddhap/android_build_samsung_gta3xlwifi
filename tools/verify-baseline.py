#!/usr/bin/env python3
"""Read-only baseline verification; records no credentials or user data."""
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('/srv/android')
OUT = ROOT / 'artifacts/lineage-21-arm64'
EXPECTED = {
    'kernel': ('src/lineage-21.0/device/samsung/gta3xlwifi/prebuilt/Image', '9827c8ac986f7497428ac27e9bc309ac8b62ee08fbb414e6d0c81653537ea4a2'),
    'vendor': ('vendor-stock/images/vendor.img', '4cc684231b4a1c355169cea61b4ea5196401bc5f68c7f74a32c1ec290abc0006'),
    'dtbo': ('src/lineage-21.0/device/samsung/gta3xlwifi/prebuilt/dtbo.img', 'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b'),
    'rom': ('artifacts/lineage-21/public-release-20261005/lineage-21.0-20261005-UNOFFICIAL-gta3xlwifi.zip', '94110cab46fa1edf908914dfbcc3c910ec5e5e16f306a810e13e673d3d5b597b'),
    'recovery': ('artifacts/lineage-21/public-release-20261005/twrp-3.7.1_12-gta3xlwifi.img', '391c36b92f65f39a87d476452195129a33e8f59a25566c367fa73a04cbcc7de7'),
    'vbmeta': ('artifacts/lineage-21/public-release-20261005/vbmeta-disabled.img', '3e679bb0b8b2e6fb5d94d8316846b7459eead2209cee8f038cbbdda8c6483750'),
}

def sha(path):
    with path.open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

report = {'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'inputs': {}, 'repositories': {}}
for name, (relative, expected) in EXPECTED.items():
    path = ROOT / relative
    actual = sha(path)
    report['inputs'][name] = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': actual, 'expected_sha256': expected, 'matches': actual == expected}
    if actual != expected:
        raise SystemExit(f'Baseline mismatch: {name}')
repos = {
    'integration': ('github-upload-lineage21/android_build_samsung_gta3xlwifi', '021e84a7fb2695ccefb440f4e8df2121df7a86d4'),
    'device': ('github-upload-lineage21/android_device_samsung_gta3xlwifi', 'ba0cffa79e32f7a0fee3afc033669e8df1cd9c0c'),
    'kernel': ('github-upload-lineage21/android_kernel_samsung_gta3xlwifi', 'b65ca196aab02b3ab7102c499a226b20095ba03b'),
    'vendor': ('github-upload-lineage21/android_vendor_samsung_gta3xlwifi', 'fd64f9be0c5bdddcd8b6b59f1c71cc0a732ce96a'),
}
for name, (relative, expected) in repos.items():
    path = ROOT / relative
    rev = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    status = subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True).strip()
    report['repositories'][name] = {'path': str(path), 'commit': rev, 'expected': expected, 'clean': not status}
    if rev != expected or status:
        raise SystemExit(f'Published repository differs: {name}')
report['disk'] = dict(zip(('total_bytes', 'used_bytes', 'free_bytes'), shutil.disk_usage(ROOT)))
report['hardware_tested_arm64'] = False
OUT.mkdir(parents=True, exist_ok=True)
(OUT / 'baseline.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
