#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select an explicitly checked ION policy cache, retaining previous and original vendor inputs.
No kernel, vendor executable, key, device or userdata changes are performed.
"""
import fcntl,hashlib,json,shutil,subprocess,sys
from pathlib import Path
O=Path(sys.argv[1]);assert not O.exists()
A=Path('/srv/android/artifacts/lineage-24.0-arm64');T=Path('/srv/android/src/lineage-24.0-arm64');P=Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
old=A/'runtime13-inputs-20261117-01/report.json';r=json.loads(old.read_text());assert r['passed']
V=A/'ion-vendor-composition-20261117-01';S=A/'ion-policy-strict-20261117-02';v=json.loads((V/'report.json').read_text());assert v['passed'] and v['all_other_contents_and_security_metadata_identical'] and v['original_vendor_unchanged']
f=S/'strict/report.json';s=json.loads(f.read_text());assert s['passed_strict'] and not s['explicit_input_overrides'] and s['results'][0]['neverallow_checks_enabled'] and '-N' not in s['results'][0]['command'];assert sha(f)==v['strict_report_sha256']
for x in s['inputs']:assert sha(Path(x['path']))==x['sha256']
f=S/'contexts/report.json';c=json.loads(f.read_text());assert c['passed']
for name,h in c['inputs_sha256'].items():assert sha(Path(name))==h
f=S/'assertions.json';n=json.loads(f.read_text());assert n['passed'] and n['candidate_report_sha256']==sha(S/'strict/report.json') and n['candidate_assertions_and_constraints']==5881 and not n['permissive_domains']
B=T/'device/samsung/gta3xlwifi/prebuilt';assert {n:sha(B/n) for n in r['after']}==r['after']
for name,h in r['before'].items():assert sha(A/'runtime-input-selection-20261116-01/original-prebuilts'/name)==h
assert sha(V/'vendor.img')==v['vendor_sparse_sha256'];O.mkdir();snap=P/'snapshots/port-20261117-15'
subprocess.run([sys.executable,str(P/'tools/audit-port.py'),str(T),str(snap),str(O/'source-before.json')],check=True)
shutil.copyfile(B/'vendor.img',O/'previous-vendor.img');previous=r['after'].copy();r['after']['vendor.img']=v['vendor_sparse_sha256']
r['proofs_sha256']={str(f):sha(f) for f in [A/'kernel-uid-receipt-build-20261115-01/report.json',V/'report.json',S/'strict/report.json',S/'contexts/report.json',S/'assertions.json']}
r.update(source_snapshot=str(snap),previous_selected_prebuilts=previous,inherited_runtime_selection_sha256=sha(old),runtime_prebuilts_changed=True,source_transition_scope=__doc__,flash_ready=False)
(O/'selection.json').write_text(json.dumps(r,indent=2)+'\n')
temp=B/'vendor.img.ion.tmp';assert not temp.exists();shutil.copyfile(V/'vendor.img',temp);assert sha(temp)==r['after']['vendor.img'];temp.replace(B/'vendor.img')
assert {n:sha(B/n) for n in r['after']}==r['after'];assert sha(O/'previous-vendor.img')==previous['vendor.img']
subprocess.run([sys.executable,str(P/'tools/audit-port.py'),str(T),str(snap),str(O/'source-after.json')],check=True)
(O/'report.json').write_text(json.dumps(r,indent=2)+'\n');print('Selected explicitly validated ION cache; original and previous vendor images retained')
