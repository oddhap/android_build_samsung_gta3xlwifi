#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib,json,shutil,subprocess
A=Path('/srv/android/artifacts/lineage-24.0-arm64');T=Path('/srv/android/src/lineage-24.0-arm64');O=A/'legacy-shm-probe-20261117-01';O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=A/'ion-policy-strict-20261117-02/strict/report.json';r=json.loads(base.read_text());assert r['passed_strict'];cmd=r['results'][0]['command'].copy()
# Freeze all currently selected CIL bytes before future source compilation.
B=A/'legacy-shm-policy-baseline-20261117-01';B.mkdir();br=json.loads(base.read_text());bc=br['results'][0]['command']
for i,x in enumerate(br['inputs']):
 src=Path(x['path']);assert sha(src)==x['sha256'];dest=B/(str(i)+'-'+src.name);shutil.copyfile(src,dest);bc=[str(dest) if q==str(src) else q for q in bc];x['path']=str(dest)
shutil.copyfile(base.parent/'strict.policy',B/'strict.policy');br['results'][0]['command']=bc;br['frozen_from_report_sha256']=sha(base);(B/'report.json').write_text(json.dumps(br,indent=2)+'\n')
upstream=T/'system/sepolicy/vendor/ashmem/ashmem_allow.te';assert 'allow domain ashmem_libcutils_device:chr_file open;' in upstream.read_text();assert 'vendor API level of 202504 or lower' in upstream.read_text()
cil=O/'legacy-shm.cil';cil.write_text('(allow bootanim ion_device (chr_file (getattr open read ioctl lock map watch watch_reads)))\n(allow domain ashmem_libcutils_device (chr_file (open)))\n')
cmd[cmd.index('-o')+1]=str(O/'strict.policy');cmd.append(str(cil));assert '-N' not in cmd;p=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(p.stdout+p.stderr);assert p.returncode==0,p.stderr
r['inputs']+=[dict(path=str(cil),sha256=sha(cil))];r['results'][0].update(command=cmd,compiled_policy_sha256=sha(O/'strict.policy'));r.update(isolated_extra_legacy_compatibility=True,upstream_old_vendor_rule_sha256=sha(upstream));(O/'report.json').write_text(json.dumps(r,indent=2)+'\n')
queries=[]
for s in ['bootanim','system_server','zygote','audioserver','platform_app','priv_app','untrusted_app']:
 for target,perm,expect in [('ashmem_libcutils_device','open','allow'),('ashmem_device','open','deny'),('device','open','deny')]:
  queries.append(dict(source='u:r:'+s+':s0',target='u:object_r:'+target+':s0',**{'class':'chr_file'},permission=perm,expected=expect))
for p in ['getattr','open','read','ioctl','map']:queries.append(dict(source='u:r:bootanim:s0',target='u:object_r:ion_device:s0',**{'class':'chr_file'},permission=p,expected='allow'))
(O/'queries.json').write_text(json.dumps(queries,indent=2)+'\n');print('PASS isolated old-vendor ashmem compatibility and observed bootanim ION rules; current assertions enforced')
