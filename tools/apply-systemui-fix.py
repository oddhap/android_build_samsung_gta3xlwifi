#!/usr/bin/env python3
"""Apply the status-bar listener lifetime fix to the pinned source revision."""
import argparse
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--top', type=Path, default=Path('/srv/android/src/lineage-19.1'))
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
project = args.top / 'frameworks/base'
patch = Path(__file__).resolve().parent.parent / 'patches/lineage-19.1/systemui-tuner-lifecycle.patch'
head = subprocess.check_output(['git', '-C', str(project), 'rev-parse', 'HEAD'], text=True).strip()
if head != '5f6b8d6098f8d858d1450db45c350c7ba08ae455':
    raise SystemExit(f'Unexpected frameworks/base revision {head}; review before applying')
command = ['git', '-C', str(project), 'apply']
if subprocess.run(command + ['--reverse', '--check', str(patch)], capture_output=True).returncode == 0:
    print('SystemUI listener lifetime patch already applied')
else:
    subprocess.run(command + ['--check', str(patch)], check=True)
    if not args.check:
        subprocess.run(command + [str(patch)], check=True)
        print('SystemUI listener lifetime patch applied')
