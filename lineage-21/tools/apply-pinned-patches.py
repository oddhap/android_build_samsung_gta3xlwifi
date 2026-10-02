#!/usr/bin/env python3
"""Verify every patch and pinned revision before applying the platform port."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--top', type=Path, default=Path('/srv/android/src/lineage-21.0'))
parser.add_argument('--check-only', action='store_true')
args = parser.parse_args()
port = Path(__file__).resolve().parent.parent
records = json.loads((port / 'notes/source-lock.json').read_text())
pending = []
for record in records:
    repo = args.top / record['project']
    patch = port / 'patches' / record['patch']
    if hashlib.sha256(patch.read_bytes()).hexdigest() != record['sha256']:
        raise SystemExit(f'Patch checksum mismatch: {patch.name}')
    head = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    if head != record['revision']:
        raise SystemExit(f'Unexpected source revision: {record["project"]}: {head}')
    command = ['git', '-C', str(repo), 'apply', '--check']
    reverse = subprocess.run(command + ['--reverse', str(patch)], capture_output=True)
    if reverse.returncode == 0:
        print(f'{record["project"]}: already applied')
        continue
    forward = subprocess.run(command + [str(patch)], capture_output=True, text=True)
    if forward.returncode:
        raise SystemExit(f'Review local changes in {record["project"]}:\n{forward.stderr}')
    pending.append((repo, patch))
    print(f'{record["project"]}: clean application verified')
if not args.check_only:
    for repo, patch in pending:
        subprocess.run(['git', '-C', str(repo), 'apply', str(patch)], check=True)
print('All pinned patches verified' + (' and applied.' if not args.check_only else '.'))
