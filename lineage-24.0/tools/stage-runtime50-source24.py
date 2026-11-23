#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed snapshot50 change on top of snapshot49.

source: the 4.4 kernel has no userfaultfd, so ART runs the concurrent-copying
        (read-barrier) GC. PRODUCT_ENABLE_UFFD_GC was "default" and the build has
        no kernel version file, so build/soong/scripts/uffd_gc_utils.py assumed
        CMC ('<unknown-kernel>' -> True): every boot image/odex was dexpreopted with
        -Xgc:CMC (oat header concurrent-copying=false) and ro.dalvik.vm.enable_uffd_gc
        was true. The runtime rejects that code ("read barrier state mismatch",
        executable false), so the framework and all apps ran interpreted/JIT and the
        on-device dexopt kept producing unusable code. Set PRODUCT_ENABLE_UFFD_GC :=
        false in the product makefile (device.mk is hash-bound by older checks).
        Build-configuration only; no code, policy, vendor or kernel change.
"""
import hashlib
import json
from pathlib import Path
import subprocess

root = Path('/srv/android')
src = root/'src/lineage-24.0-arm64'
art = root/'artifacts/lineage-24.0-arm64'
port = root/'ports/lineage-24.0-arm64/lineage-24.0'
base = port/'snapshots'
project = 'device/samsung/gta3xlwifi'
ANCHOR = 'PRODUCT_SHIPPING_API_LEVEL := 28\n'
ADDITION = '''
# The 4.4 kernel has no userfaultfd: ART falls back to the concurrent-copying GC,
# which cannot execute code dexpreopted for CMC. The build cannot read the kernel
# version, and "default" then assumes CMC, so state it explicitly.
PRODUCT_ENABLE_UFFD_GC := false
'''


def read(path):
    return json.loads(path.read_text())


work = art/'runtime50-source-selection-20261122-01'
work.mkdir()
before = base/'port-20261122-49'
after = base/'port-20261122-50'
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert read(work/'source-before.json')['passed']
assert not after.exists()
target = src/project/'lineage_gta3xlwifi.mk'
original = target.read_bytes()
text = original.decode()
assert text.count(ANCHOR) == 1 and 'UFFD' not in text
new = text.replace(ANCHOR, ANCHOR+ADDITION)
(work/'edits.json').write_text(json.dumps({str(target): {
    'before_sha256': hashlib.sha256(original).hexdigest(),
    'after_sha256': hashlib.sha256(new.encode()).hexdigest()}}, indent=2)+'\n')
projects = [r['project'] for r in read(before/'source-lock.json')]
try:
    target.write_text(new)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    target.write_bytes(original)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
print('PASS staged snapshot50:', after)
