#!/usr/bin/env python3
"""Restore the exact reviewed kernel inputs from the private source repository."""
import hashlib
import subprocess
import tarfile
import tempfile
from pathlib import Path

repo = 'oddhap/android_kernel_samsung_gta3xlwifi'
tag = 'lineage21-baseline-kernel'
expected = '5e5d9ee0733b98dee731ba04369e8312100254753fc4f5cba57f356fc4123477'
destination = Path('/srv/android/artifacts/kernel-smoke')
files = {'Image', 'config', 'source-commit.txt', 'SHA256SUMS',
         'dts/exynos/dtbo/exynos7904-gta3xlwifi_eur_open_03.dtbo',
         'dts/exynos/dtbo/exynos7904-gta3xlwifi_eur_open_04.dtbo'}
with tempfile.TemporaryDirectory(prefix='gta3xlwifi-kernel-inputs-') as directory:
    archive_path = Path(directory) / 'kernel-inputs.tar.gz'
    subprocess.run(['gh', 'release', 'download', tag, '--repo', repo,
                    '--pattern', archive_path.name, '--dir', directory], check=True)
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != expected:
        raise SystemExit('Baseline kernel archive checksum mismatch')
    with tarfile.open(archive_path, 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) != len(files) or {m.name for m in members} != files:
            raise SystemExit('Unexpected archive members')
        if any(not m.isfile() for m in members):
            raise SystemExit('Only regular kernel input files are permitted')
        payload = {m.name: archive.extractfile(m).read() for m in members}
    sums = payload['SHA256SUMS'].decode().splitlines()
    if {row.split(maxsplit=1)[1] for row in sums} != files - {'SHA256SUMS'}:
        raise SystemExit('Incomplete input checksums')
    for row in sums:
        digest, name = row.split(maxsplit=1)
        if hashlib.sha256(payload[name]).hexdigest() != digest:
            raise SystemExit(f'Kernel input checksum mismatch: {name}')
    # Existing builds can contain additional DTBs and a broader checksum file.
    # Verify overlapping inputs before writing; preserve their checksum inventory.
    for name, data in payload.items():
        path = destination / name
        if path.exists() and name != 'SHA256SUMS' and path.read_bytes() != data:
            raise SystemExit(f'Refusing to replace a different kernel input: {path}')
    for name, data in payload.items():
        path = destination / name
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
print('Verified baseline kernel inputs restored; existing matching files preserved.')
