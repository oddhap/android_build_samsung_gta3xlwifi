#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed snapshot52 change on top of snapshot51.

source: issue oddhap/android_build_samsung_gta3xlwifi#5 (build 48, clean install,
        SM-T510): as soon as Wi-Fi connected, system_server died about every 25 s with
        "java.io.IOException: Missing real interface history: 0" from
        Gta3xlwifiStatsConsumer.prepare, reached through BatteryStatsImpl /
        WifiPowerStatsCollector. The frozen kernel bank can hold rows whose ifindex has
        no entry in the interface-name table (ifindex 0 here).
        A17 libnetworkstats BpfNetworkStats.cpp drops exactly such rows in every reader
        (parseBpfNetworkStatsDetailInternal consumes them: "these stats will be
        lost/deleted"; parseBpfNetworkStatsDevInternal and bpfGetIfaceStatsInternal skip
        them) and maybeLogUnknownIface logs one error per read at 100 000 bytes
        (MAX_UNKNOWN_IFACE_BYTES). The shim threw instead, failing the whole read.
        Fix: Gta3xlwifiStatsConsumer.prepare/readSummary and Gta3xlwifiTrafficStats.iface
        skip rows without a name and log with the same bound and text. Name-table loss,
        frozen-bank loss, counter overflow on named rows and durable-store faults still
        reject without ACK. No policy, vendor, kernel or DTBO change.
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
project = 'packages/modules/Connectivity'
server = src/project/'service/src/com/android/server'
texts = port/'tools/runtime52-stats'
BEFORE = {'Gta3xlwifiStatsConsumer.java': '713abd60e76af4faeb7eee0dd0046d97c58b3226b2e8f626b813eb0a7ffa4b3c',
          'Gta3xlwifiTrafficStats.java': '8137a7b83b12184ea7d22feb5221abcd556ece646a943ad1c75a45bf5bf566ba'}
AFTER = {'Gta3xlwifiStatsConsumer.java': '08787b8dcf54806b313284595715a8d4bd97d19c3816e131c9b150cdd417a387',
         'Gta3xlwifiTrafficStats.java': '140f1437e5c9094b7fc61cd79d2e726cd8979da0231591d0d43be216c2ed889e'}
sha = lambda b: hashlib.sha256(b).hexdigest()


def read(path):
    return json.loads(path.read_text())


work = art/'runtime52-source-selection-20261123-01'
work.mkdir()
before = base/'port-20261123-51'
after = base/'port-20261123-52'
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert read(work/'source-before.json')['passed']
assert not after.exists()
new = {}
originals = {}
for name in AFTER:
    data = (texts/name).read_bytes()
    assert sha(data) == AFTER[name], name
    new[name] = data
    originals[name] = (server/name).read_bytes()
    assert sha(originals[name]) == BEFORE[name], name
(work/'originals').mkdir()
for name, data in originals.items():
    (work/'originals'/name).write_bytes(data)
(work/'edits.json').write_text(json.dumps({str(server/n): {'before_sha256': BEFORE[n], 'after_sha256': AFTER[n]}
                                           for n in AFTER}, indent=2)+'\n')
projects = [r['project'] for r in read(before/'source-lock.json')]
try:
    for name, data in new.items():
        (server/name).write_bytes(data)
    subprocess.run(['git', '-C', src/project, 'diff', '--', *(f'service/src/com/android/server/{n}' for n in AFTER)],
                   check=True, stdout=(work/'stats.diff').open('w'))
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for name, data in originals.items():
        (server/name).write_bytes(data)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
print('PASS staged snapshot52:', after)
