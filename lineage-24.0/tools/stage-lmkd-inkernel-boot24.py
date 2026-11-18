#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare the in-kernel LMK boot handling fix outside the active Android tree."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('source', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
source = args.source.read_text()
monitor = '''        // Registration is needed only if it was skipped earlier.
        if (monitors_initialized)
            return;'''
memevent = '''static void init_memevent() {
    if (init_memevent_listener_monitoring()) {'''
assert source.count(monitor) == source.count(memevent) == 1
fixed = source.replace(monitor, '''        // The in-kernel LMK backend already handles memory pressure.
        // Only the userspace backend may have deferred monitor registration.
        if (use_inkernel_interface || monitors_initialized)
            return;''').replace(memevent, '''static void init_memevent() {
    // The in-kernel backend does not use userspace reclaim monitoring.
    // This also applies when lmkd restarts after sys.boot_completed.
    if (use_inkernel_interface) return;

    if (init_memevent_listener_monitoring()) {''')
args.output.mkdir()
(args.output / 'lmkd.cpp').write_text(fixed)
(args.output / 'lmkd.patch').write_text(''.join(difflib.unified_diff(
    source.splitlines(keepends=True), fixed.splitlines(keepends=True),
    fromfile='a/lmkd.cpp', tofile='b/lmkd.cpp')))
(args.output / 'selection.json').write_text(json.dumps({
    'before_sha256': hashlib.sha256(source.encode()).hexdigest(),
    'after_sha256': hashlib.sha256(fixed.encode()).hexdigest(),
    'source_selected': False,
}, indent=2) + '\n')
