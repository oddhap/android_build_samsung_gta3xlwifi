#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Audit a patched checkout against a captured manifest AND exact patch hashes.

Usage: audit-port.py TOP SNAPSHOT_DIR OUTPUT_JSON
Unlike setup's clean-source audit, this explicitly records reviewed dirty trees.
Ignored binary inputs are checked separately against baseline-inputs.json.
"""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args])


def audit(top, snapshot):
    top, snapshot = top.resolve(), snapshot.resolve()
    manifest = snapshot / 'port-manifest.xml'
    entries = json.loads((snapshot / 'source-lock.json').read_text())
    patches = {item['project']: item for item in entries}
    if len(patches) != len(entries):
        raise ValueError('Duplicate patch project')
    projects, seen = [], set()
    for node in ET.parse(manifest).getroot().iter('project'):
        project = node.get('path', node.get('name'))
        if (not project or project in seen or Path(project).is_absolute()
                or '..' in Path(project).parts):
            raise ValueError(f'Unsafe/duplicate project: {project}')
        seen.add(project)
        path = top / project
        if not path.resolve().is_relative_to(top):
            raise ValueError(f'External checkout: {project}')
        expected = node.get('revision', '')
        if not re.fullmatch('[0-9a-f]{40}', expected):
            raise ValueError(f'Unlocked project: {project}')
        if git(path, 'rev-parse', 'HEAD').decode().strip() != expected:
            raise ValueError(f'Unexpected HEAD: {project}')
        git(path, 'cat-file', '-e', expected + '^{commit}')
        git(path, 'cat-file', '-e', expected + '^{tree}')
        status = git(path, 'status', '--porcelain', '--untracked-files=normal')
        if item := patches.get(project):
            filename = item['patch']
            if Path(filename).name != filename or item['revision'] != expected:
                raise ValueError(f'Invalid patch lock: {project}')
            if git(path, 'ls-files', '--others', '--exclude-standard'):
                raise ValueError(f'Unreviewed untracked sources: {project}')
            patch = (snapshot / 'patches' / filename).read_bytes()
            actual = git(path, 'diff', '--binary', '--no-ext-diff', '--full-index', 'HEAD')
            if (hashlib.sha256(patch).hexdigest() != item['sha256'] or actual != patch):
                raise ValueError(f'Source differs from captured patch: {project}')
        elif status:
            raise ValueError(f'Unreviewed working-tree changes: {project}')
        alternate = Path(git(path, 'rev-parse', '--git-path',
                             'objects/info/alternates').decode().strip())
        if not alternate.is_absolute():
            alternate = path / alternate
        if alternate.exists():
            objects = alternate.resolve().parent.parent
            for line in alternate.read_text().splitlines():
                if line.strip() and not (objects / line).resolve().is_relative_to(top / '.repo'):
                    raise ValueError(f'External shared Git objects: {project}')
        projects.append({'path': project, 'revision': expected,
                         'source_state': 'reviewed-patch' if project in patches else 'clean'})
    required = {'build/make', 'build/soong', 'vendor/lineage', 'bionic', 'art',
                'bootable/deprecated-ota', 'device/samsung/gta3xlwifi',
                'kernel/samsung/gta3xlwifi', 'vendor/samsung/gta3xlwifi', 'prebuilts/vndk/v30'}
    if (missing := (required | patches.keys()) - seen):
        raise ValueError(f'Missing projects: {sorted(missing)}')
    return {'passed': True, 'checked_at_utc': datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            'project_count': len(projects), 'reviewed_patch_count': len(patches),
            'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
            'projects': projects, 'hardware_tested': False,
            'ignored_binary_inputs_audited_by_this_tool': False}


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    result = audit(Path(sys.argv[1]), Path(sys.argv[2]))
    Path(sys.argv[3]).write_text(json.dumps(result, indent=2) + '\n')
    print(f"PASS: {result['project_count']} locked projects, "
          f"{result['reviewed_patch_count']} exact reviewed patches; no external alternates")
