#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot55: e2fsck must not clear Samsung FBE files (issue #6, ported from LineageOS 21).

The Samsung 4.4 kernel (CONFIG_EXT4_PRIVATE_ENCRYPTION, Exynos FMP, fileencryption=ice)
sets EXT4_POLICY_FLAGS_PRIVATE_ALGO (0x04) in the v1 context of every non-directory
inode, never in directories. e2fsprogs 1.47.2 compares the full v1 policy, so after an
unclean shutdown fs_mgr's "e2fsck -f -y" clears every encrypted entry and moves the
files to lost+found (user 0 keys gone -> init_user0_failed). Fix: for v1 contexts,
ignore 0x04 when contents and filenames modes differ (upstream 0x04 is DIRECT_KEY,
only valid with equal modes). Same reviewed patch as lineage-21 (f6d36fc9..., blob
d7a60c7 -> 2eae7bb; e2fsck/encrypted_files.c e7d7bb63... -> c9df17f3...).

Parent is port-20261127-54. Prebuilts (kernel/vendor/dtbo) are unchanged from the
build 54 selection. No SELinux, vendor, kernel or other change."""
import hashlib, json, re, subprocess, sys
from pathlib import Path
src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261127-54', port/'snapshots/port-20261128-55'
patch = Path(sys.argv[1])  # tools/runtime55-e2fsck/external_e2fsprogs.patch
work = art/'runtime55-source-selection-20261128-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert json.loads((work/'source-before.json').read_text())['passed']
assert not after.exists()
proj = 'external/e2fsprogs'
e2 = src/proj
target = e2/'e2fsck/encrypted_files.c'
PATCH = 'f6d36fc92402c546ed019d61c3669b5917809059f427f8ac59e427721456720c'
OLD = 'e7d7bb632f51eed645f4f5703bd1070b1c612fc17f6e1c2e66ff82a4dc076098'
NEW = 'c9df17f3cec8981b7372ef9431ae9694013d96466a254ab1674459f102878cdf'
assert sha(patch) == PATCH, sha(patch)
assert sha(target) == OLD, sha(target)
assert subprocess.check_output(['git', '-C', e2, 'status', '--porcelain']) == b''
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
assert proj not in projects
(work/'edits.json').write_text(json.dumps({str(target): {'before_sha256': OLD, 'after_sha256': NEW,
    'patch': str(patch), 'patch_sha256': PATCH}}, indent=2)+'\n')
try:
    subprocess.run(['git', '-C', e2, 'apply', '--check', patch.resolve()], check=True)
    subprocess.run(['git', '-C', e2, 'apply', patch.resolve()], check=True)
    assert sha(target) == NEW, sha(target)
    assert subprocess.check_output(['git', '-C', e2, 'status', '--porcelain']) == b' M e2fsck/encrypted_files.c\n'
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after,
                    *projects, proj], check=True)
    lock = json.loads((after/'source-lock.json').read_text())
    row = [r for r in lock if r['project'] == proj]
    assert len(row) == 1, row
    # capture-port.py stores --full-index diffs; apart from the full blob ids the bytes
    # must equal the reviewed lineage-21 patch.
    captured = (after/'patches'/row[0]['patch']).read_bytes()
    short = re.sub(rb'^index ([0-9a-f]{7})[0-9a-f]{33}\.\.([0-9a-f]{7})[0-9a-f]{33}',
                   rb'index \1..\2', captured, count=1, flags=re.M)
    assert short == patch.read_bytes(), 'captured e2fsprogs patch differs from the reviewed patch'
    assert len(lock) == len(projects) + 1
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    subprocess.run(['git', '-C', e2, 'checkout', '--', 'e2fsck/encrypted_files.c'], check=True)
    assert sha(target) == OLD
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime54-inputs-20261127-01/report.json'
r = json.loads(p.read_text())
assert r['passed'] and r['original_rollback_copies_verified']
for name, digest in r['after'].items():
    assert sha(src/'device/samsung/gta3xlwifi/prebuilt'/name) == digest, name
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p), runtime_prebuilts_changed=False)
out = art/'runtime55-inputs-20261128-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot55 e2fsck Samsung policy flag:', after)
