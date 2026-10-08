#!/usr/bin/env python3
"""Detect incomplete indexes left by interrupted initial repo checkouts."""
import concurrent.futures
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

top = Path('/srv/android/src/lineage-21.0-arm64')
port = Path('/srv/android/ports/lineage-21-arm64/lineage-21')
projects = ET.parse(port / 'notes/pinned-build-manifest.xml').getroot().findall('project')

def audit(project):
    path = project.get('path', project.get('name'))
    result = subprocess.run(['git', '-C', str(top/path), 'diff', '--cached', '--name-status', '-z'], capture_output=True, check=True)
    fields = result.stdout.decode().rstrip('\0').split('\0') if result.stdout else []
    if not fields:
        return None
    entries = list(zip(fields[::2], fields[1::2]))
    return {'project': path, 'revision': project.get('revision'), 'count': len(entries),
            'all_deletions': all(status == 'D' for status, _ in entries),
            'sample': entries[:10]}

with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    affected = [result for result in pool.map(audit, projects) if result]
report = {'projects_checked': len(projects), 'affected': affected, 'passed': not affected}
Path('/srv/android/artifacts/lineage-21-arm64/checkout-index-check.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2), flush=True)
raise SystemExit(1 if affected else 0)
