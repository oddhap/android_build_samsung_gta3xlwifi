#!/usr/bin/env python3
"""Compare authoritative signing files to a private pre-port hash manifest."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('manifest', type=Path)
parser.add_argument('--root', type=Path, default=Path('/srv/android/signing'))
args = parser.parse_args()
expected = json.loads(args.manifest.read_text())
assert expected and all(name.startswith('gta3xlwifi/') for name in expected)
actual_names = {str(path.relative_to(args.root)) for path in
                (args.root/'gta3xlwifi').rglob('*') if path.is_file()}
assert actual_names == set(expected), 'Signing file set changed'
for name, digest in expected.items():
    assert hashlib.sha256((args.root/name).read_bytes()).hexdigest() == digest, name
print(f'All {len(expected)} signing files match the private pre-port manifest.')
