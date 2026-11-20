#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Freeze the actual snapshot31 strict-policy inputs as an immutable baseline.

The snapshot31 strict report referenced build-output CIL files that a later
build overwrites. Recover each input by exact SHA256 from its current path or
from the snapshot31 target-files archive, copy it into a new directory and write
a report identical to the original except for the immutable input paths."""
import hashlib, json, sys, zipfile
from pathlib import Path
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
src = A/'firmware-policy-strict-20261120-03/strict/report.json'
tf = A/'runtime31-ota-build-20261120-01/target-files.zip'
out = Path(sys.argv[1]); assert not out.exists(); out.mkdir()
sha = lambda b: hashlib.sha256(b).hexdigest()
r = json.loads(src.read_text())
assert r['passed_strict'] and not r['explicit_input_overrides']
prod = '/srv/android/src/lineage-24.0-arm64/out/target/product/gta3xlwifi/'
recovered = []
with zipfile.ZipFile(tf) as z:
    for i, item in enumerate(r['inputs']):
        p = Path(item['path'])
        data = p.read_bytes() if p.exists() else b''
        origin = 'current-path'
        if sha(data) != item['sha256']:
            assert item['path'].startswith(prod), item['path']
            rel = item['path'][len(prod):]
            top, rest = rel.split('/', 1)
            data = z.read(top.upper() + '/' + rest)
            origin = 'runtime31-target-files'
        assert sha(data) == item['sha256'], item['path']
        dest = out/f'{i}-{p.name}'
        dest.write_bytes(data)
        recovered.append({'index': i, 'original_path': item['path'], 'origin': origin, 'sha256': item['sha256']})
        item['path'] = str(dest)
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
(out/'freeze.json').write_text(json.dumps({'passed': True, 'source_report': str(src),
    'source_report_sha256': sha(src.read_bytes()), 'target_files_sha256': sha(tf.read_bytes()),
    'inputs': recovered}, indent=2)+'\n')
print('PASS frozen snapshot31 strict inputs:', sum(x['origin'] != 'current-path' for x in recovered), 'recovered from target-files')
