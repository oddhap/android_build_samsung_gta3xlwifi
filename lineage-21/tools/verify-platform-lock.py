#!/usr/bin/env python3
"""Require every synced platform project to match the immutable manifest."""
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

port = Path('/srv/android/ports/lineage-21-arm64/lineage-21')
artifacts = Path('/srv/android/artifacts/lineage-21-arm64')
pinned = port / 'notes/pinned-build-manifest.xml'
actual = artifacts / 'platform-manifest.xml'

def projects(path):
    result = {}
    for project in ET.parse(path).getroot().findall('project'):
        name = project.get('path', project.get('name'))
        revision = project.get('revision')
        if name in result or len(revision or '') != 40 or any(c not in '0123456789abcdef' for c in revision):
            raise RuntimeError(f'{path}: duplicate path or non-immutable revision: {name}')
        result[name] = {'name': project.get('name'), 'revision': revision}
    return result

expected = projects(pinned)
observed = projects(actual)
if expected != observed:
    differences = {name: {'expected': expected.get(name), 'actual': observed.get(name)}
                   for name in expected.keys() | observed.keys() if expected.get(name) != observed.get(name)}
    raise RuntimeError(json.dumps(differences, indent=2))
report = {'passed': True, 'projects_checked': len(expected),
          'pinned_manifest_sha256': hashlib.sha256(pinned.read_bytes()).hexdigest(),
          'synced_manifest_sha256': hashlib.sha256(actual.read_bytes()).hexdigest()}
(artifacts / 'platform-lock-check.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
