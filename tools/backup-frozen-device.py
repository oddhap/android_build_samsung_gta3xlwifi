#!/usr/bin/env python3
"""Capture read-only userdata/EFS blocks from TWRP and validate gzip and length.

Prepare manually first: stop the recovery GUI (SIGSTOP), stop crypto services,
sync, remount data/EFS read-only, and set both block devices read-only. This
script never prepares, flashes, or resumes the device. Backups are private.
"""
import argparse
import gzip
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

os.umask(0o077)
adb = '/opt/homebrew/bin/adb'
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, default=Path('/Users/oddi/Documents/Samsung-ARM64/.private/device-baseline'))
args = parser.parse_args()
directory = args.output.resolve()
private = Path(__file__).resolve().parent.parent/'.private'
assert directory.is_relative_to(private.resolve()), 'Backups must remain under .private'
directory.mkdir(parents=True, exist_ok=True, mode=0o700)
block = '/dev/block/platform/13500000.dwmmc0/by-name/'

def shell(command):
    return subprocess.check_output([adb, 'shell', command], text=True).strip()

def frozen():
    for name in ('userdata', 'efs'):
        assert shell(f'blockdev --getro {block}{name}') == '1', f'{name} is writable'
    mounts = shell('cat /proc/mounts').splitlines()
    for mountpoint in ('/data', '/mnt/vendor/efs'):
        entries = [line.split() for line in mounts if line.split()[1] == mountpoint]
        assert len(entries) <= 1
        assert all('ro' in entry[3].split(',') for entry in entries), mountpoint

frozen()
report = {'source': 'existing ARM32 installation in TWRP', 'partitions': {},
          'encrypted_raw_backup': True, 'physical_arm64_tested': False}
from datetime import datetime, timezone
report['started_at_utc'] = datetime.now(timezone.utc).isoformat()
for name in ('efs', 'userdata'):
    expected = int(shell(f'blockdev --getsize64 {block}{name}'))
    destination = directory / f'{name}.img.gz'
    if destination.exists():
        raise RuntimeError(f'Refusing to overwrite {destination}')
    partial = destination.with_suffix('.gz.partial')
    command = f'set -o pipefail; dd if={block}{name} bs=4194304 2>/tmp/arm64-backup-{name}.log | gzip -1'
    print(f'Capturing {name}: {expected} raw bytes', flush=True)
    with partial.open('xb') as output:
        process = subprocess.Popen([adb, 'exec-out', command], stdout=output, stderr=subprocess.PIPE)
        while process.poll() is None:
            time.sleep(30)
            print(f'{name}: {partial.stat().st_size} compressed bytes written', flush=True)
        error = process.stderr.read().decode(errors='replace')
        if process.returncode:
            raise RuntimeError(f'{name}: adb/backup exited {process.returncode}: {error}')
        output.flush()
        os.fsync(output.fileno())
    frozen()
    print(f'Validating {name} gzip checksum and complete raw length', flush=True)
    raw_hash = hashlib.sha256()
    raw_bytes = 0
    with gzip.open(partial, 'rb') as source:
        while chunk := source.read(8 * 1024 * 1024):
            raw_bytes += len(chunk)
            raw_hash.update(chunk)
    assert raw_bytes == expected, (name, raw_bytes, expected)
    compressed_hash = hashlib.sha256()
    with partial.open('rb') as source:
        while chunk := source.read(8 * 1024 * 1024):
            compressed_hash.update(chunk)
    partial.rename(destination)
    report['partitions'][name] = {'path': str(destination), 'raw_bytes': raw_bytes,
                                 'raw_sha256': raw_hash.hexdigest(),
                                 'gzip_bytes': destination.stat().st_size,
                                 'gzip_sha256': compressed_hash.hexdigest(),
                                 'gzip_crc_and_length_validated': True}
    (directory / 'data-backup.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'{name} backup verified', flush=True)
print('Both partition backups verified; device remains frozen in recovery.', flush=True)
