#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Capture reviewed tracked-source patches and a revision-locked Repo manifest.

Usage: capture-port.py TOP NEW_OUTPUT_DIR PROJECT [PROJECT ...]
Untracked source files must be reviewed separately, not silently published.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args])


def capture(top, out, projects, parent=None):
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
    known = {}
    reused_style = []
    if parent:
        parent = parent.resolve()
        for row in json.loads((parent / 'source-lock.json').read_text()):
            if row['project'] in known or Path(row['patch']).name != row['patch']:
                raise ValueError('Invalid parent snapshot record')
            data = (parent / 'patches' / row['patch']).read_bytes()
            if hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError('Parent snapshot patch hash mismatch')
            known[row['project']] = (row, data)
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
        diff = git(path, 'diff', '--binary', '--no-ext-diff', '--full-index', 'HEAD')
        approved = known.get(project)
        if approved and approved[0]['revision'] == revision and approved[1] == diff:
            # Preserve already-reviewed frozen upstream bytes, including their
            # original whitespace. Any changed byte still takes the normal check.
            reused_style.append({'project': project, 'sha256': approved[0]['sha256']})
        else:
            subprocess.run(['git', '-C', str(path), 'diff', '--check', 'HEAD'], check=True)
        if not diff:
            continue
        filename = project.replace('/', '_') + '.patch'
        (patches / filename).write_bytes(diff)
        subprocess.run(['git', '-C', str(path), 'apply', '--reverse', '--check',
                        str((patches / filename).resolve())], check=True)
        locked.append({'project': project, 'revision': revision, 'patch': filename,
                       'sha256': hashlib.sha256(diff).hexdigest()})
    (out / 'source-lock.json').write_text(json.dumps(locked, indent=2) + '\n')
    if parent:
        (out / 'capture-parent.json').write_text(json.dumps({
            'parent': str(parent),
            'parent_lock_sha256': hashlib.sha256((parent / 'source-lock.json').read_bytes()).hexdigest(),
            'byte_exact_style_approvals_reused': reused_style,
            'changed_patches_style_checked': True}, indent=2) + '\n')
    print(f'Captured {len(locked)} tracked-source patches; {len(revisions)} locked projects')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-snapshot', type=Path,
                        help='Reuse whitespace review only for byte-exact already-locked patches')
    parser.add_argument('top', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('projects', nargs='+')
    args = parser.parse_args()
    capture(args.top, args.output, args.projects, args.parent_snapshot)
