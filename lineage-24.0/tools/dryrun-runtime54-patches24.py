#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot54: test every snapshot53 patch against the fetched lineage-24.0
revision using a private temporary index. No working tree or ref is changed."""
import json, os, subprocess, sys, tempfile
from pathlib import Path
T = Path('/srv/android/src/lineage-24.0-arm64')
snap = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0/snapshots/port-20261123-53')
out = Path(sys.argv[1]); assert not out.exists(); out.mkdir()
own = {'device/samsung/gta3xlwifi', 'kernel/samsung/gta3xlwifi', 'vendor/samsung/gta3xlwifi'}
rows = []
for row in json.loads((snap/'source-lock.json').read_text()):
    p = row['project']; path = T/p; patch = snap/'patches'/row['patch']
    g = lambda *a, **k: subprocess.run(['git', '-C', str(path), *a], capture_output=True, text=True, **k)
    old = row['revision']
    new = old if p in own else g('rev-parse', 'refs/remotes/m/lineage-24.0').stdout.strip()
    assert len(new) == 40, (p, new)
    ahead = int(g('rev-list', '--count', f'{old}..{new}').stdout.strip() or 0)
    behind = int(g('rev-list', '--count', f'{new}..{old}').stdout.strip() or 0)
    touched = g('diff', '--name-only', old, new).stdout.split()
    with tempfile.TemporaryDirectory(dir=out) as d:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(d)/'index'))
        subprocess.run(['git', '-C', str(path), 'read-tree', new], env=env, check=True)
        clean = subprocess.run(['git', '-C', str(path), 'apply', '--cached', '--check', str(patch)],
                               env=env, capture_output=True, text=True)
        conflicts = []
        if clean.returncode:
            three = subprocess.run(['git', '-C', str(path), 'apply', '--cached', '--3way', str(patch)],
                                   env=env, capture_output=True, text=True)
            conflicts = sorted({l.split()[-1] for l in (three.stdout+three.stderr).splitlines()
                                if 'conflict' in l.lower() or l.startswith('error')})
            status = 'applies-3way' if three.returncode == 0 else 'conflict'
        else:
            status = 'clean'
    rows.append({'project': p, 'old': old, 'new': new, 'upstream_commits': ahead,
                 'old_not_in_new': behind, 'upstream_files_changed': len(touched),
                 'status': status, 'conflicts': conflicts})
    print(f"{status:13} +{ahead:<4} -{behind:<3} {p} {' '.join(conflicts)[:200]}", flush=True)
(out/'report.json').write_text(json.dumps({'patches': rows,
    'all_clean': all(r['status'] == 'clean' for r in rows)}, indent=2)+'\n')
