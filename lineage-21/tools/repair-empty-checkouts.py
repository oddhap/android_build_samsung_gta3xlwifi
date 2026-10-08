#!/usr/bin/env python3
"""Complete only pinned, empty-index checkouts found by the index audit."""
import concurrent.futures
import json
import shutil
import subprocess
from pathlib import Path

top = Path('/srv/android/src/lineage-21.0-arm64')
artifacts = Path('/srv/android/artifacts/lineage-21-arm64')
port = Path('/srv/android/ports/lineage-21-arm64/lineage-21')
records = json.loads((artifacts/'checkout-index-check.json').read_text())['affected']
patched = {record['project'] for record in json.loads((port/'notes/source-lock.json').read_text())}
for record in records:
    path = top / record['project']
    assert record['all_deletions'] and record['project'] not in patched, record
    head = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    assert head == record['revision'], record
    assert not subprocess.check_output(['git', '-C', str(path), 'ls-files', '-z']), record
backup = artifacts / 'checkout-index-backups'
backup.mkdir(exist_ok=True)
for record in records:
    path = top / record['project']
    index = (path/'.git/index').resolve()
    if index.is_file():
        destination = backup / (record['project'].replace('/', '_') + '.index')
        if destination.exists():
            raise RuntimeError(f'Index backup already exists: {destination}')
        shutil.copy2(index, destination)

def repair(record):
    path = top / record['project']
    print('Completing pinned checkout: ' + record['project'], flush=True)
    subprocess.run(['git', '-C', str(path), 'read-tree', '--reset', '-u', 'HEAD'], check=True)
    assert not subprocess.check_output(['git', '-C', str(path), 'diff', '--cached', '--name-status', '-z'])
    print('Completed: ' + record['project'], flush=True)

records.sort(key=lambda record: record['project'] != 'prebuilts/build-tools')
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    list(pool.map(repair, records))
print('All interrupted empty-index checkouts repaired.', flush=True)
