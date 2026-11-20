#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind snapshot29 UI/touch host proofs to snapshot31 sources after an upstream sync.

For every source file whose hash changed, require that:
  * the reviewed port patch hunks for that file are byte-identical in the
    snapshot29 and snapshot31 patches (the port change itself is unchanged);
  * the file in the checkout equals upstream-new + identical port hunks, i.e.
    the only delta comes from the recorded upstream commit range;
  * the upstream diff for that file is recorded verbatim in the new proof.
Unchanged files must keep their original hash. Physical/runtime evidence flags
are carried over unchanged; nothing is re-tested or relaxed by this tool.
"""
import hashlib, json, re, subprocess, sys, xml.etree.ElementTree as ET
from pathlib import Path

T = Path('/srv/android/src/lineage-24.0-arm64')
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
S = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0/snapshots')
label = sys.argv[1]
proofs = sys.argv[2:]
O = A / label
O.mkdir()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def revision(snapshot, path):
    for p in ET.parse(S / snapshot / 'port-manifest.xml').getroot().iter('project'):
        if p.get('path', p.get('name')) == path:
            return p.get('revision')
    raise KeyError(path)


def project_of(name):
    lock = json.loads((S / 'port-20261120-31/source-lock.json').read_text())
    best = max((x['project'] for x in lock if name.startswith(x['project'] + '/')), key=len)
    return best, next(x['patch'] for x in lock if x['project'] == best)


def file_hunks(patch_text, rel):
    parts = re.split(r'(?m)^(?=diff --git )', patch_text)
    found = [p for p in parts if p.startswith('diff --git a/%s b/%s\n' % (rel, rel))]
    assert len(found) <= 1, rel
    # Drop the index line and hunk line offsets: blob ids and line numbers
    # legitimately move with the upstream base. Hunk bodies (context, removed
    # and added lines) and the hunk function context must stay byte-identical.
    return '\n'.join(re.sub(r'^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@', '@@ @@', l)
                     for l in (found[0] if found else '').splitlines() if not l.startswith('index '))


summary = {}
for proof_rel in proofs:
    path = A / proof_rel
    proof = json.loads(path.read_text())
    assert proof['passed']
    changed = {}
    new_sources = {}
    for name, digest in proof['source_sha256'].items():
        actual = sha((T / name).read_bytes())
        new_sources[name] = actual
        if actual == digest:
            continue
        project, patch = project_of(name)
        rel = name[len(project) + 1:]
        old_rev, new_rev = revision('port-20261118-29', project), revision('port-20261120-31', project)
        assert old_rev != new_rev, (name, 'changed without upstream revision change')
        old_h = file_hunks((S / 'port-20261118-29/patches' / patch).read_text(), rel)
        new_h = file_hunks((S / 'port-20261120-31/patches' / patch).read_text(), rel)
        assert old_h == new_h, (name, 'port patch hunks differ')
        git = ['git', '-C', str(T / project)]
        upstream = subprocess.run(git + ['show', new_rev + ':' + rel], capture_output=True, check=True).stdout
        if old_h:
            r = subprocess.run(git + ['diff', '--no-color', new_rev, '--', rel], capture_output=True, check=True).stdout.decode()
            assert file_hunks(r, rel) == new_h, (name, 'checkout delta is not exactly the port hunks')
        else:
            assert upstream == (T / name).read_bytes(), (name, 'unpatched file differs from upstream')
        udiff = subprocess.run(git + ['diff', '--no-color', old_rev, new_rev, '--', rel], capture_output=True, check=True).stdout.decode()
        assert udiff
        changed[name] = dict(before=digest, after=actual, project=project, upstream_from=old_rev,
                             upstream_to=new_rev, port_hunks_identical=True, port_hunks_present=bool(old_h),
                             upstream_diff=udiff)
    assert changed, proof_rel
    out = dict(proof)
    out['source_sha256'] = new_sources
    out.update(rebound_from=str(path), rebound_from_sha256=sha(path.read_bytes()),
               upstream_sync_rebinding=changed, rebinding_scope=__doc__)
    dest = O / Path(proof_rel).name
    dest.write_text(json.dumps(out, indent=2) + '\n')
    summary[proof_rel] = sorted(changed)
(O / 'report.json').write_text(json.dumps({'passed': True, 'rebound': summary}, indent=2) + '\n')
print('PASS rebound host proofs with identical port hunks:', json.dumps(summary))
