#!/usr/bin/env python3
"""Apply reviewed compatibility patches to the pinned LineageOS checkout.

Run only while the Android build is stopped. --check makes no changes.
"""
import argparse
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--top', type=Path, default=Path('/srv/android/src/lineage-19.1'))
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
patch_dir = Path(__file__).resolve().parent.parent / 'patches/lineage-19.1'
projects = (
    ('system/bpf', 'bb1485f836d496570a337f6d7b809a3e44191f71', 'bpf-legacy-kernel.patch'),
    ('system/netd', 'bb0df47d330bed1f1bfa59ffa54834da4c87b043', 'netd-legacy-network.patch'),
    ('hardware/interfaces', 'ae469cee0dce6d71489588126a15da8e67a50102', 'device-kernel-profile.patch'),
)
pending = []
for relative, revision, filename in projects:
    project = args.top / relative
    patch = patch_dir / filename
    head = subprocess.check_output(['git', '-C', str(project), 'rev-parse', 'HEAD'], text=True).strip()
    if head != revision:
        raise SystemExit(f'{relative}: unexpected source revision {head}; review before applying')
    command = ['git', '-C', str(project), 'apply']
    if subprocess.run(command + ['--reverse', '--check', str(patch)], capture_output=True).returncode == 0:
        print(f'{relative}: patch already applied')
        continue
    subprocess.run(['git', '-C', str(project), 'diff', '--exit-code', '--quiet'], check=True)
    subprocess.run(command + ['--check', str(patch)], check=True)
    pending.append((relative, command, patch))
    print(f'{relative}: patch checked')
if not args.check:
    for relative, command, patch in pending:
        subprocess.run(command + [str(patch)], check=True)
        print(f'{relative}: patch applied')
