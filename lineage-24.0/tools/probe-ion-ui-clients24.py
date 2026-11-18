#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Strict isolated ION read-interface candidate for five physically observed clients.

Snapshot22 reaches boot_completed, then the retained gralloc fails ion_open with
EACCES in these concrete domains; launcher/SystemUI/Settings rendering aborts.
Keep rendering guards, all current assertions, vendor symbols and enforcement.
No write access, generic-device grant or access for unobserved app domains added.
"""
from pathlib import Path
import fcntl,hashlib,json,shutil,subprocess
A=Path('/srv/android/artifacts/lineage-24.0-arm64');T=Path('/srv/android/src/lineage-24.0-arm64');O=A/'ion-ui-clients-probe-20261117-01';B=A/'ion-ui-clients-policy-baseline-20261117-01';assert not O.exists() and not B.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir();B.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=A/'legacy-shm-policy-strict-20261117-01/strict/report.json';br=json.loads(base.read_text());assert br['passed_strict'] and not br['explicit_input_overrides'];bc=br['results'][0]['command'];assert '-N' not in bc
for i,x in enumerate(br['inputs']):
 src=Path(x['path']);assert sha(src)==x['sha256'];dest=B/(str(i)+'-'+src.name);shutil.copyfile(src,dest);bc=[str(dest) if q==str(src) else q for q in bc];x['path']=str(dest)
shutil.copyfile(base.parent/'strict.policy',B/'strict.policy');br['results'][0]['command']=bc;br['frozen_from_report_sha256']=sha(base);(B/'report.json').write_text(json.dumps(br,indent=2)+'\n')
clients=['system_server','mediaswcodec','platform_app','priv_app','system_app'];perms=['getattr','open','read','ioctl','lock','map','watch','watch_reads']
cil=O/'observed-ion-ui-clients.cil';cil.write_text(''.join('(allow '+s+' ion_device (chr_file ('+' '.join(perms)+')))\n' for s in clients))
cmd=bc.copy();cmd[cmd.index('-o')+1]=str(O/'strict.policy');cmd.append(str(cil));x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
br['inputs']+=[dict(path=str(cil),sha256=sha(cil))];br['results'][0].update(command=cmd,compiled_policy_sha256=sha(O/'strict.policy'));br.update(isolated_extra_legacy_compatibility=True,scope=__doc__,observed_clients=clients,no_neverallow_bypass=True,no_new_write_grants=True,hardware_candidate_tested=False);(O/'report.json').write_text(json.dumps(br,indent=2)+'\n')
queries=[]
for s in clients:
 for target,perm,expect in [('ion_device',p,'allow') for p in ['getattr','open','read','ioctl','map']]+[('device',p,'deny') for p in ['open','read','ioctl','map']]+[('ion_device','write','observe')]:
  queries.append(dict(source='u:r:'+s+':s0',target='u:object_r:'+target+':s0',**{'class':'chr_file'},permission=perm,expected=expect))
for s in ['untrusted_app','isolated_app']:
 for perm in ['open','read','ioctl','map','write']:queries.append(dict(source='u:r:'+s+':s0',target='u:object_r:ion_device:s0',**{'class':'chr_file'},permission=perm,expected='deny'))
(O/'queries.json').write_text(json.dumps(queries,indent=2)+'\n');print('PASS strict isolated ION candidate for five observed clients; original current/vendor assertions retained')
