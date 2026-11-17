#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind unchanged kernel/vendor inputs to the reviewed genuine legacy mapper selection delta."""
import fcntl,hashlib,json,shutil,subprocess,sys
from pathlib import Path
O=Path(sys.argv[1]);assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
A=Path('/srv/android/artifacts/lineage-24.0-arm64');T=Path('/srv/android/src/lineage-24.0-arm64');P=Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
old=A/'runtime12-inputs-20261117-01/report.json';r=json.loads(old.read_text());assert r['passed']
D=A/'legacy-gralloc-bool-source-selection-20261117-01';delta=json.loads((D/'selection.json').read_text())
expected={'device/samsung/gta3xlwifi/BoardConfig.mk'}
assert set(delta['files'])==expected and delta['policy_source_changed']==False and json.loads((D/'report.json').read_text())['passed']
assert delta['parent']==str(P/'snapshots/port-20261117-12') and not delta['vendor_and_kernel_selection_changed']
for name,h in delta['proof_reports_sha256'].items():assert sha(Path(name))==h
for name,entry in delta['files'].items():assert sha(T/name)==entry['after_sha256']
B=T/'device/samsung/gta3xlwifi/prebuilt';assert {n:sha(B/n) for n in r['after']}==r['after']
for n,h in r['before'].items():assert sha(A/'runtime-input-selection-20261116-01/original-prebuilts'/n)==h
for name,h in r['proofs_sha256'].items():assert sha(Path(name))==h
O.mkdir(parents=True);snapshot=P/'snapshots/port-20261117-13'
subprocess.run([sys.executable,str(P/'tools/audit-port.py'),str(T),str(snapshot),str(O/'source-audit.json')],check=True)
r.update(source_snapshot=str(snapshot),inherited_runtime_selection_sha256=sha(old),runtime_prebuilts_changed=False,source_transition_scope='Only the device selects existing libui legacy Gralloc2 support. Genuine mapper loading remains required; platform API properties, policy, readiness, failure guards, kernel, vendor and FBE remain unchanged.',source_delta_selection_sha256=sha(D/'selection.json'),source_audit_sha256=sha(O/'source-audit.json'),flash_ready=False)
(O/'report.json').write_text(json.dumps(r,indent=2)+'\n');print('Bound unchanged runtime pair to exact genuine legacy mapper selection snapshot')
