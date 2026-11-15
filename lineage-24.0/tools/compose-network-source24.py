#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select an explicitly hash-verified source composition and capture a new exact snapshot.

No kernel/prebuilt/policy/device source, signing material or user data is changed.
Backups and the complete parent snapshot remain available for source rollback.
"""
import argparse,fcntl,hashlib,json,shutil,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','ports','composition','parent','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();P=a.ports.resolve();C=a.composition.resolve();O=a.output.resolve();N=a.snapshot.resolve();assert not O.exists() and not N.exists() and not C.is_relative_to(T) and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();audit=Path(__file__).with_name('audit-port.py')
subprocess.run([sys.executable,str(audit),str(T),str(a.parent),str(O/'source-before.json')],check=True)
labels=['clat-coordinator-native-20261115-02','permission-install-identity-native-20261114-01','permission-install-identity-api-20261114-01','xtables-iface-stats-native-20261113-01','private-aidl-jarjar-20261115-02'];proofs={};allowed={}
for label in labels:
 f=Path('/srv/android/artifacts/lineage-24.0-arm64')/label/'report.json';r=json.loads(f.read_text());assert r['passed'];proofs[str(f)]=sha(f)
 for name,h in r.get('inputs_sha256',r.get('input_sha256',{})).items():
  if name in allowed:assert allowed[name]==h
  allowed[name]=h
records=json.loads((C/'local-inputs.json').read_text())['files'];assert len(records)==109
projects={x.get('path',x.get('name')):x.get('revision') for x in ET.parse(a.parent/'port-manifest.xml').getroot().iter('project')};pending=[];files={}
allowed_roots=['system/netd/','external/iptables/','packages/modules/Connectivity/','packages/modules/DnsResolver/','frameworks/base/']
for rel,item in records.items():
 assert any(rel.startswith(x) for x in allowed_roots) and not Path(rel).is_absolute() and '..' not in Path(rel).parts
 src=C/'files'/rel;assert sha(src)==item['sha256'];target=T/rel;assert target.resolve().is_relative_to(T)
 origin=item['origin']
 if item.get('composed'):
  baseline=C/'baseline'/rel;assert sha(target)==sha(baseline)
 else:
  if origin.startswith('work/'):original=P/origin.removeprefix('work/')
  elif rel.endswith('jarjar-excludes.txt'):original=Path('/srv/android/artifacts/lineage-24.0-arm64/private-aidl-jarjar-20261115-02/jarjar-excludes.txt')
  else:raise AssertionError(origin)
  assert str(original) in allowed,('No source proof',original)
  assert sha(original)==allowed[str(original)]==sha(src),('Changed source',original)
 project=max((n for n in projects if rel.startswith(n+'/')),key=len);inside=rel[len(project)+1:]
 old=sha(target) if target.exists() else None
 if old is not None:
  backup=O/'before'/rel;backup.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(target,backup)
 files[rel]={'project':project,'path':inside,'before_sha256':old,'after_sha256':sha(src),'provenance':item}
 pending.append((src,target,project,inside,old))
# Explicitly preserve ignored Android binary inputs and device Git HEAD.
prebuilt=T/'device/samsung/gta3xlwifi/prebuilt';bins={n:sha(prebuilt/n) for n in ['Image','vendor.img','dtbo.img']};expected={'Image':'33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553','vendor.img':'a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a','dtbo.img':'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b'};assert bins==expected
(O/'selection.json').write_text(json.dumps({'scope':__doc__,'parent':str(a.parent),'files':files,'proof_reports_sha256':proofs,'prebuilts':bins,'policy_changed':False,'flash_ready':False},indent=2)+'\n')
# All preconditions and backups exist before the first source mutation.
for src,target,project,inside,old in pending:
 target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,target)
 if old is None:subprocess.run(['git','-C',str(T/project),'add','--intent-to-add','--',inside],check=True)
N.mkdir();(N/'patches').mkdir();shutil.copyfile(a.parent/'port-manifest.xml',N/'port-manifest.xml');entries=[]
for project,rev in sorted(projects.items()):
 data=subprocess.check_output(['git','-C',str(T/project),'diff','--binary','--no-ext-diff','--full-index','HEAD'])
 if data:
  name=project.replace('/','_')+'.patch';(N/'patches'/name).write_bytes(data);entries.append({'project':project,'revision':rev,'patch':name,'sha256':hashlib.sha256(data).hexdigest()})
(N/'source-lock.json').write_text(json.dumps(entries,indent=2)+'\n');(N/'capture-parent.json').write_text(json.dumps({'parent_snapshot':a.parent.name,'parent_manifest_sha256':sha(a.parent/'port-manifest.xml'),'parent_lock_sha256':sha(a.parent/'source-lock.json'),'composition_selection_sha256':sha(O/'selection.json'),'proof_reports_sha256':proofs,'kernel_prebuilts_and_policy_unchanged':True},indent=2)+'\n')
subprocess.run([sys.executable,str(audit),str(T),str(N),str(N/'port-audit.json')],check=True);shutil.copyfile(N/'port-audit.json',O/'source-after.json')
assert {n:sha(prebuilt/n) for n in bins}==bins
for rel,item in files.items():assert sha(T/rel)==item['after_sha256']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'files_selected':len(files),'project_count':len(projects),'reviewed_patches':len(entries),'snapshot':str(N),'selection_sha256':sha(O/'selection.json'),'device_prebuilts_and_policy_unchanged':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('Selected',len(files),'verified sources;',len(entries),'exact project patches')
