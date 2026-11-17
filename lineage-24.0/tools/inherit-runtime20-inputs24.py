#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind unchanged compiled policy/kernel/vendor to an explicit metadata storage bootstrap.
Compiled CIL inputs must still match the strict linked vendor cache after the
build. Changed file contexts require a fresh actual context validation afterward.
"""
from pathlib import Path
import fcntl,hashlib,json,subprocess,sys
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');P=Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0');O=Path(sys.argv[1]);assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
f=A/'runtime19-inputs-20261117-01/report.json';r=json.loads(f.read_text());assert r['passed'];d=A/'aconfig-cache-source-selection-20261117-01';s=json.loads((d/'selection.json').read_text());assert s['policy_source_changed'] and not s['compiled_CIL_rules_changed'];assert set(s['files'])=={'device/samsung/gta3xlwifi/BoardConfig.mk','device/samsung/gta3xlwifi/rootdir/init.exynos7904.rc','device/samsung/gta3xlwifi/sepolicy/private/file_contexts'};assert json.loads((d/'report.json').read_text())['passed']
for name,h in r['proofs_sha256'].items():assert sha(Path(name))==h
for name,x in s['files'].items():assert sha(T/name)==x['after_sha256']
for name,h in s['proof_reports_sha256'].items():assert sha(Path(name))==h
assert {n:sha(T/'device/samsung/gta3xlwifi/prebuilt'/n) for n in r['after']}==r['after']
strict=A/'legacy-shm-policy-strict-20261117-01/strict/report.json';sr=json.loads(strict.read_text());assert sr['passed_strict'] and not sr['explicit_input_overrides']
for x in sr['inputs']:assert sha(Path(x['path']))==x['sha256']
# Old context-validation inputs will change, so do not pretend that its proof
# still validates the new contexts. Carry the staged validated replacement,
# require a new actual context check after this build, and retain strict CIL proofs.
r['proofs_sha256']={name:h for name,h in r['proofs_sha256'].items() if not name.endswith('/contexts/report.json')};r['proofs_sha256'].update(s['proof_reports_sha256'])
O.mkdir();snap=P/'snapshots/port-20261117-20';subprocess.run([sys.executable,str(P/'tools/audit-port.py'),str(T),str(snap),str(O/'source-audit.json')],check=True)
r.update(source_snapshot=str(snap),inherited_runtime_selection_sha256=sha(f),source_delta_selection_sha256=sha(d/'selection.json'),runtime_prebuilts_changed=False,source_transition_scope=__doc__,compiled_CIL_inputs_expected_unchanged=sr['inputs'],fresh_actual_context_validation_required=True,flash_ready=False)
(O/'report.json').write_text(json.dumps(r,indent=2)+'\n');print('Bound unchanged runtime/cache to explicit metadata bootstrap; fresh built-context validation mandatory')
