#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply a capture-port.py snapshot to its exact base revisions without resets.

Usage: apply-port.py TOP SNAPSHOT_DIR
An already applied identical patch is accepted. Other local edits are refused.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args])


def apply(top, snapshot):
    top, snapshot = top.resolve(), snapshot.resolve()
    pending = []
    seen = set()
    for item in json.loads((snapshot / 'source-lock.json').read_text()):
        project = item['project']
        filename = item['patch']
        if (project in seen or Path(project).is_absolute() or '..' in Path(project).parts
                or Path(filename).name != filename):
            raise ValueError('Unsafe or duplicate patch entry')
        seen.add(project)
        path = top / project
        if not path.resolve().is_relative_to(top):
            raise ValueError(f'Checkout outside source tree: {project}')
        patch = snapshot / 'patches' / filename
        data = patch.read_bytes()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError(f'Patch checksum mismatch: {filename}')
        if git(path, 'rev-parse', 'HEAD').decode().strip() != item['revision']:
            raise ValueError(f'Unexpected source revision: {project}')
        if git(path, 'ls-files', '--others', '--exclude-standard'):
            raise ValueError(f'Untracked source files: {project}')
        current = git(path, 'diff', '--binary', '--no-ext-diff', 'HEAD')
        if current == data:
            print(f'Already applied: {project}')
        elif current:
            raise ValueError(f'Unrecognized local modifications: {project}')
        else:
            subprocess.run(['git', '-C', str(path), 'apply', '--check', str(patch)], check=True)
            pending.append((path, patch))
    # Validate every project before changing any worktree.
    for path, patch in pending:
        subprocess.run(['git', '-C', str(path), 'apply', str(patch)], check=True)
        print(f'Applied: {path.relative_to(top)}')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    apply(Path(sys.argv[1]), Path(sys.argv[2]))
