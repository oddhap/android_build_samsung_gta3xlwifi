#!/usr/bin/env python3
"""Reuse reference-clone shallow boundaries after an interrupted repo sync.

Only initialized new repositories are touched. Each boundary must already be
available through the new repository's object alternates. The reference tree
is never modified. Run with all repo/git fetch processes stopped.
"""
import hashlib
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

old = Path('/srv/android/src/lineage-21.0/.repo/projects')
new = Path('/srv/android/src/lineage-21.0-arm64/.repo/projects')
reused = []
manifest = Path('/srv/android/ports/lineage-21-arm64/lineage-21/notes/pinned-build-manifest.xml')
projects = ET.parse(manifest).getroot().findall('project')
for project in projects:
    source = old / (project.get('path', project.get('name')) + '.git') / 'shallow'
    if not source.is_file():
        continue
    relative = source.relative_to(old)
    destination = new / relative
    gitdir = destination.parent
    if not (gitdir / 'config').is_file() or destination.exists():
        continue
    boundaries = source.read_text().splitlines()
    if not boundaries:
        continue
    for commit in boundaries:
        if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
            raise RuntimeError(f'Invalid boundary in {source}')
        subprocess.run(['git', f'--git-dir={gitdir}', 'cat-file', '-e', commit + '^{commit}'], check=True)
    shutil.copyfile(source, destination)
    reused.append({'gitdir': str(gitdir), 'boundaries': boundaries,
                   'sha256': hashlib.sha256(destination.read_bytes()).hexdigest()})
report = {'reference_read_only': True, 'count': len(reused), 'repositories': reused}
Path('/srv/android/artifacts/lineage-21-arm64/shallow-reuse.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'Reused validated shallow boundaries in {len(reused)} initialized repositories.')
