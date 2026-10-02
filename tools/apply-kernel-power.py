#!/usr/bin/env python3
"""Apply the dedicated framework CPU QoS endpoints to the pinned source revision."""
import argparse
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--top', type=Path, default=Path('/srv/android/src/kernel-gta3xlwifi'))
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
project = args.top
patch_dir = Path(__file__).resolve().parent.parent / 'patches/kernel'
head = subprocess.check_output(['git', '-C', str(project), 'rev-parse', 'HEAD'], text=True).strip()
patches = [patch_dir / name for name in ('framework-cpu-qos.patch', 'framework-gpu-floor.patch')]
already = all(subprocess.run(['git', '-C', str(project), 'apply', '--reverse', '--check', str(patch)], capture_output=True).returncode == 0 for patch in patches)
if head != '00e4b9481434f9b0b644925a9bb2feaf3940219d' and not already:
    raise SystemExit(f'Unexpected kernel revision {head}; review before applying')
for filename in ('framework-cpu-qos.patch', 'framework-gpu-floor.patch'):
    patch = patch_dir / filename
    command = ['git', '-C', str(project), 'apply']
    if subprocess.run(command + ['--reverse', '--check', str(patch)], capture_output=True).returncode == 0:
        print(f'{filename}: already applied')
    else:
        subprocess.run(command + ['--check', str(patch)], check=True)
        if not args.check:
            subprocess.run(command + [str(patch)], check=True)
            print(f'{filename}: applied')
