#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the strict ION cache to an OTA-only reviewed vendor identity delta."""
from pathlib import Path
import fcntl,hashlib,json,subprocess,sys
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');P=Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0');O=Path(sys.argv[1]);assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
f=A/'runtime16-inputs-20261117-01/report.json';r=json.loads(f.read_text());assert r['passed'];d=A/'vendor-ota-binding-source-selection-20261117-01';s=json.loads((d/'selection.json').read_text());assert not s['policy_source_changed'] and set(s['files'])=={'device/samsung/gta3xlwifi/releasetools.py'};assert json.loads((d/'report.json').read_text())['passed']
for name,h in r['proofs_sha256'].items():assert sha(Path(name))==h
assert {n:sha(T/'device/samsung/gta3xlwifi/prebuilt'/n) for n in r['after']}==r['after']
for name,x in s['files'].items():assert sha(T/name)==x['after_sha256']
O.mkdir();snap=P/'snapshots/port-20261117-17';subprocess.run([sys.executable,str(P/'tools/audit-port.py'),str(T),str(snap),str(O/'source-audit.json')],check=True)
r.update(source_snapshot=str(snap),inherited_runtime_selection_sha256=sha(f),source_delta_selection_sha256=sha(d/'selection.json'),runtime_prebuilts_changed=False,source_transition_scope=__doc__,flash_ready=False)
(O/'report.json').write_text(json.dumps(r,indent=2)+'\n');print('Bound unchanged strict ION runtime pair to reviewed OTA vendor binding snapshot')
