#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind the aconfig-cache host proof to the snapshot31 host_init_verifier.

The upstream lineage-24.0 sync rebuilt out/host/linux-x86/bin/host_init_verifier
from updated system/core. The original proof (aconfig-cache-host-20261117-03)
cannot be regenerated verbatim because its composition inputs were the
pre-application sources. This tool instead:
  * requires every reviewed source and every other bound input to remain
    byte-identical to the original proof;
  * re-runs the actual rebuilt host_init_verifier on the actual, unchanged
    device bootstrap (init.exynos7904.rc) and requires exit 0;
  * writes a new report that records the old and new verifier hashes.
No flag, policy, source file, service or partition is changed.
"""
import hashlib, json, subprocess, sys
from pathlib import Path

T = Path('/srv/android/src/lineage-24.0-arm64')
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
label = sys.argv[1]
O = A / label
O.mkdir()
old_path = A / 'aconfig-cache-host-20261117-03/report.json'
old = json.loads(old_path.read_text())
assert old['passed'] and not old['compiled_policy_rules_changed'] and not old['flag_values_or_services_disabled']


def sha(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as s:
        for b in iter(lambda: s.read(1048576), b''):
            h.update(b)
    return h.hexdigest()


for name, digest in old['source_sha256'].items():
    assert sha(T / name) == digest, ('reviewed source changed', name)
verifier = str(T / 'out/host/linux-x86/bin/host_init_verifier')
changed = {}
for name, digest in old['inputs_sha256'].items():
    actual = sha(name)
    if actual != digest:
        changed[name] = {'before': digest, 'after': actual}
assert set(changed) <= {verifier}, ('unexpected changed inputs', sorted(changed))
rc = T / 'device/samsung/gta3xlwifi/rootdir/init.exynos7904.rc'
r = subprocess.run([verifier, str(rc)], capture_output=True, text=True)
(O / 'init-verifier.log').write_text(r.stdout + r.stderr)
assert r.returncode == 0, r.stdout + r.stderr
report = dict(old)
report['inputs_sha256'] = {name: sha(name) for name in old['inputs_sha256']}
report.update(
    scope=__doc__,
    rebound_from_report=str(old_path),
    rebound_from_report_sha256=sha(old_path),
    changed_inputs=changed,
    rerun_actual_init_parser_exit=r.returncode,
    rerun_bootstrap_sha256=sha(rc),
    compiled_policy_rules_changed=False,
    flag_values_or_services_disabled=False,
    flash_ready=False,
)
(O / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS rebound aconfig host proof: unchanged sources/inputs, rebuilt host_init_verifier exit 0;',
      'changed:', sorted(changed))
