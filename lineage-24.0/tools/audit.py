#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify every locked checkout and its objects, without changing any checkout."""
import datetime
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


def audit(top, manifest):
    top = top.resolve()
    root = ET.parse(manifest).getroot()
    projects = []
    seen = set()
    for node in root.iter('project'):
        relative = node.get('path', node.get('name'))
        if not relative or Path(relative).is_absolute() or '..' in Path(relative).parts:
            raise ValueError(f'Unsafe project path: {relative}')
        if relative in seen:
            raise ValueError(f'Duplicate project: {relative}')
        seen.add(relative)
        checkout = top / relative
        expected = node.get('revision', '')
        if not re.fullmatch(r'[0-9a-f]{40}', expected):
            raise ValueError(f'Project not revision-locked: {relative}')
        actual = git(checkout, 'rev-parse', 'HEAD')
        if actual != expected:
            raise ValueError(f'HEAD differs from manifest: {relative}')
        git(checkout, 'cat-file', '-e', actual + '^{commit}')
        git(checkout, 'cat-file', '-e', actual + '^{tree}')
        if git(checkout, 'status', '--porcelain', '--untracked-files=normal'):
            raise ValueError(f'Uncommitted source changes: {relative}')
        alternate = Path(git(checkout, 'rev-parse', '--git-path', 'objects/info/alternates'))
        if not alternate.is_absolute(): alternate = checkout / alternate
        if alternate.exists():
            # Repo normally shares objects between projects and project-objects
            # inside this checkout. Only cross-checkout alternates are forbidden.
            object_dir = alternate.resolve().parent.parent
            for entry in alternate.read_text().splitlines():
                if not entry.strip(): continue
                target = (object_dir / entry).resolve()
                if not target.is_relative_to(top / '.repo'):
                    raise ValueError(f'External shared Git objects: {relative}')
        projects.append({'path': relative, 'name': node.get('name'), 'revision': actual})
    if not projects:
        raise ValueError('Manifest contains no projects')
    required = {'build/make', 'build/soong', 'vendor/lineage', 'bionic', 'art',
                'bootable/deprecated-ota', 'device/samsung/gta3xlwifi',
                'kernel/samsung/gta3xlwifi', 'vendor/samsung/gta3xlwifi'}
    if required - seen:
        raise ValueError(f'Missing required projects: {sorted(required - seen)}')
    return {
        'passed': True, 'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'project_count': len(projects), 'projects': projects,
        'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
        'compiled': False, 'hardware_tested': False,
    }


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('Usage: audit.py TOP LOCKED_MANIFEST OUTPUT_JSON')
    result = audit(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
    Path(sys.argv[3]).write_text(json.dumps(result, indent=2) + '\n')
    print(f"Verified {result['project_count']} locked, clean, independent checkouts")
