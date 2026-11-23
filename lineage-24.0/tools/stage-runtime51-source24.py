#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed snapshot51 change on top of snapshot50.

source: the bounded touch/launch CPU-GPU boost (device/samsung/gta3xlwifi/power,
        linked into libandroid_servers.so) closed its controls and stayed disabled for
        the life of system_server after the first failed open/write. On build 50 it was
        found dead before a reboot (big cluster at 936 MHz during touch, no requests
        logged) and the reason had rotated out of the main log. Power.cpp now suspends:
        it releases the requests, logs op/control/errno to the main and system buffers,
        and reopens the controls on a later request after a 1 s .. 60 s backoff
        (new RetryBackoff.h, host test gta3xlwifi-power-retry-test in Android.bp).
        Floors, durations, endpoints, policy, vendor and kernel are unchanged.
        New source texts: tools/runtime51-power/ (hash-checked here).
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
texts = port/'tools/runtime51-power'
BEFORE = {'Power.cpp': '53dea82de88a7dcb8d89162016a92b8cbd5137743ef2e8b1d654668732bc9afc',
          'Android.bp': '77d1bd598bd72b6214697f9f5319be7361111f3fc531554ca1c8a423a1215050',
          'RetryBackoff.h': None, 'RetryBackoffTest.cpp': None}
AFTER = {'Power.cpp': 'ba68deb7bb92708ce6c806689af969700e7d2f4b90f182584600d7b95fc745b1',
         'Android.bp': 'ed3ebd0c2ce06307618920169b6f11cbf3f199a5cfc69b291b5622e875759d88',
         'RetryBackoff.h': '060b85e565c87a27d2046a05cd356406627be884e68dc6f336b9d37d001372b3',
         'RetryBackoffTest.cpp': 'd307f5d53e2d03a0512da9e44024d261cc70eae4787130c75416dc818174161a'}
sha = lambda b: hashlib.sha256(b).hexdigest()


def read(path):
    return json.loads(path.read_text())


work = art/'runtime51-source-selection-20261123-01'
work.mkdir()
before = base/'port-20261122-50'
after = base/'port-20261123-51'
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert read(work/'source-before.json')['passed']
assert not after.exists()
power = src/project/'power'
new = {}
originals = {}
for name in AFTER:
    data = (texts/name).read_bytes()
    assert sha(data) == AFTER[name], name
    new[name] = data
    target = power/name
    if BEFORE[name] is None:
        assert not target.exists(), target
    else:
        originals[name] = target.read_bytes()
        assert sha(originals[name]) == BEFORE[name], name
(work/'edits.json').write_text(json.dumps({str(power/n): {'before_sha256': BEFORE[n], 'after_sha256': AFTER[n]}
                                           for n in AFTER}, indent=2)+'\n')
added = [f'power/{n}' for n in AFTER if BEFORE[n] is None]
projects = [r['project'] for r in read(before/'source-lock.json')]
try:
    for name, data in new.items():
        (power/name).write_bytes(data)
    subprocess.run(['git', '-C', src/project, 'add', '--intent-to-add', '--', *added], check=True)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    subprocess.run(['git', '-C', src/project, 'rm', '--cached', '--quiet', '--ignore-unmatch', '--', *added])
    for name in added:
        (src/project/name).unlink(missing_ok=True)
    for name, data in originals.items():
        (power/name).write_bytes(data)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
print('PASS staged snapshot51:', after)
