#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Capture reviewed tracked-source patches and a revision-locked Repo manifest.

Usage: capture-port.py TOP NEW_OUTPUT_DIR PROJECT [PROJECT ...]
Untracked source files must be reviewed separately, not silently published.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args])


def capture(top, out, projects):
    top = top.resolve()
    if out.exists():
        raise ValueError('Output must be a new directory')
    out.mkdir(parents=True)
    patches = out / 'patches'
    patches.mkdir()
    subprocess.run(['repo', 'manifest', '-r', '-o', str((out / 'port-manifest.xml').resolve())],
                   cwd=top, check=True)
    manifest = ET.parse(out / 'port-manifest.xml').getroot()
    revisions = {p.get('path', p.get('name')): p.get('revision')
                 for p in manifest.iter('project')}
    locked = []
    for project in projects:
        if project not in revisions or Path(project).is_absolute() or '..' in Path(project).parts:
            raise ValueError(f'Project not in locked manifest: {project}')
        path = top / project
        revision = git(path, 'rev-parse', 'HEAD').decode().strip()
        if revision != revisions[project]:
            raise ValueError(f'HEAD differs from manifest: {project}')
        if git(path, 'ls-files', '--others', '--exclude-standard'):
            raise ValueError(f'Unreviewed untracked source files: {project}')
        subprocess.run(['git', '-C', str(path), 'diff', '--check', 'HEAD'], check=True)
        diff = git(path, 'diff', '--binary', '--no-ext-diff', '--full-index', 'HEAD')
        if not diff:
            continue
        filename = project.replace('/', '_') + '.patch'
        (patches / filename).write_bytes(diff)
        subprocess.run(['git', '-C', str(path), 'apply', '--reverse', '--check',
                        str((patches / filename).resolve())], check=True)
        locked.append({'project': project, 'revision': revision, 'patch': filename,
                       'sha256': hashlib.sha256(diff).hexdigest()})
    (out / 'source-lock.json').write_text(json.dumps(locked, indent=2) + '\n')
    print(f'Captured {len(locked)} tracked-source patches; {len(revisions)} locked projects')


if __name__ == '__main__':
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    capture(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3:])
