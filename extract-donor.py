#!/usr/bin/env python3
"""Extract only named firmware images; never execute firmware payloads."""
import hashlib
import json
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

ROOT = Path('/srv/android/vendor-donor/a305gt')
archives = list((ROOT / 'firmware').glob('*.zip'))
if len(archives) != 1:
    raise SystemExit('Expected one completed SM-A305GT firmware ZIP')
archive = archives[0]
images = ROOT / 'images'
images.mkdir(exist_ok=True)

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(8 * 1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

selected = {'vendor.img.lz4', 'boot.img.lz4', 'dtbo.img.lz4', 'dt.img.lz4'}
with zipfile.ZipFile(archive) as z:
    ap = [n for n in z.namelist() if Path(n).name.startswith('AP_') and n.endswith('.tar.md5')]
    if len(ap) != 1:
        raise SystemExit('Expected one AP tar.md5')
    found = set()
    with z.open(ap[0]) as stream, tarfile.open(fileobj=stream, mode='r|') as tar:
        for member in tar:
            if member.name not in selected:
                continue
            if not member.isfile():
                raise SystemExit('Selected image is not a regular file')
            target = images / member.name
            with tar.extractfile(member) as src, target.open('wb') as dst:
                shutil.copyfileobj(src, dst, 8 * 1024 * 1024)
            found.add(member.name)
    if found != selected:
        raise SystemExit(f'Missing images: {selected - found}')
for name in sorted(selected):
    subprocess.run(['lz4', '-dqf', str(images / name), str(images / name[:-4])], check=True)
subprocess.run(['simg2img', str(images / 'vendor.img'), str(images / 'vendor.raw.img')], check=True)
record = {'model': 'SM-A305GT', 'region': 'ZTO', 'version': 'A305GTVJU8CWE1/A305GTOWO8CWE1/A305GTVJU8CWE1/A305GTVJU8CWE1', 'archive': {'name': archive.name, 'bytes': archive.stat().st_size, 'sha256': sha(archive)}, 'images': {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(images.iterdir()) if p.is_file()}}
(ROOT / 'firmware-lock.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))
