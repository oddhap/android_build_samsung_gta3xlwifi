#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select an explicitly hash-verified source composition and capture a new exact snapshot.

Select existing libui legacy mapper support for the retained genuine HIDL2 HALs.
No SELinux policy, vendor image or kernel input is modified; no BPF readiness is set.
No vendor image, kernel, signing material or user data is changed.
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
proof=Path('/srv/android/artifacts/lineage-24.0-arm64/legacy-gralloc-host-20261117-02/report.json');r=json.loads(proof.read_text());assert r['boolean_config_registration_validated'];assert sha(T/'build/make/core/config.mk')==r['production_make_config_sha256'];assert r['passed'] and r['Android17_default_rejects_only_mapper2_reproduced'] and r['legacy_path_requires_actual_loaded_mapper'] and r['no_available_mapper_remains_fatal'] and r['modern_mapper_preference_preserved'] and not r['policy_kernel_vendor_crypto_changed']
for rel,h in r['source_sha256'].items():assert sha(C/'files'/rel)==h
assert sha(T/'frameworks/native/libs/ui/GraphicBufferMapper.cpp')==r['unchanged_mapper_source_sha256']
assert sha(T/'frameworks/native/libs/ui/Android.bp')==r['unchanged_android_bp_sha256']
proofs={str(proof):sha(proof)}
records=json.loads((C/'selection.json').read_text())['files'];assert len(records)==1
projects={x.get('path',x.get('name')):x.get('revision') for x in ET.parse(a.parent/'port-manifest.xml').getroot().iter('project')};pending=[];files={}
allowed_roots=['device/samsung/gta3xlwifi/BoardConfig.mk']
for rel,item in records.items():
 assert rel in allowed_roots and not Path(rel).is_absolute() and '..' not in Path(rel).parts
 src=C/'files'/rel;baseline=C/'baseline'/rel;target=T/rel
 assert sha(src)==item['after'] and sha(baseline)==item['before'] and sha(target)==item['before']
 assert target.resolve().is_relative_to(T)
 project=max((n for n in projects if rel.startswith(n+'/')),key=len);inside=rel[len(project)+1:]
 backup=O/'before'/rel;backup.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(target,backup)
 files[rel]={'project':project,'path':inside,'before_sha256':sha(target),'after_sha256':sha(src)}
 pending.append((src,target,project,inside,sha(target)))
# Explicitly preserve ignored Android binary inputs and device Git HEAD.
prebuilt=T/'device/samsung/gta3xlwifi/prebuilt';bins={n:sha(prebuilt/n) for n in ['Image','vendor.img','dtbo.img']};expected={'Image':'7ece8d6fd70870811abfe5fd9f947311506f97233491b4016cde441de3578aec','vendor.img':'2b40b8c71ce02b432ae25c9664f8460ebefc5c0955226b2fdb74ed16c2d11353','dtbo.img':'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b'};assert bins==expected
(O/'selection.json').write_text(json.dumps({'scope':__doc__,'parent':str(a.parent),'files':files,'proof_reports_sha256':proofs,'prebuilts':bins,'policy_source_changed':False,'vendor_and_kernel_selection_changed':False,'flash_ready':False},indent=2)+'\n')
# All preconditions and backups exist before the first source mutation.
for src,target,project,inside,old in pending:
 target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,target)
 if old is None:subprocess.run(['git','-C',str(T/project),'add','--intent-to-add','--',inside],check=True)
N.mkdir();(N/'patches').mkdir();shutil.copyfile(a.parent/'port-manifest.xml',N/'port-manifest.xml');entries=[]
for project,rev in sorted(projects.items()):
 data=subprocess.check_output(['git','-C',str(T/project),'diff','--binary','--no-ext-diff','--full-index','HEAD'])
 if data:
  name=project.replace('/','_')+'.patch';(N/'patches'/name).write_bytes(data);entries.append({'project':project,'revision':rev,'patch':name,'sha256':hashlib.sha256(data).hexdigest()})
(N/'source-lock.json').write_text(json.dumps(entries,indent=2)+'\n');(N/'capture-parent.json').write_text(json.dumps({'parent_snapshot':a.parent.name,'parent_manifest_sha256':sha(a.parent/'port-manifest.xml'),'parent_lock_sha256':sha(a.parent/'source-lock.json'),'composition_selection_sha256':sha(O/'selection.json'),'proof_reports_sha256':proofs,'kernel_and_vendor_prebuilts_unchanged':True},indent=2)+'\n')
subprocess.run([sys.executable,str(audit),str(T),str(N),str(N/'port-audit.json')],check=True);shutil.copyfile(N/'port-audit.json',O/'source-after.json')
assert {n:sha(prebuilt/n) for n in bins}==bins
for rel,item in files.items():assert sha(T/rel)==item['after_sha256']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'files_selected':len(files),'project_count':len(projects),'reviewed_patches':len(entries),'snapshot':str(N),'selection_sha256':sha(O/'selection.json'),'kernel_and_vendor_prebuilts_unchanged':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('Selected',len(files),'verified sources;',len(entries),'exact project patches')
