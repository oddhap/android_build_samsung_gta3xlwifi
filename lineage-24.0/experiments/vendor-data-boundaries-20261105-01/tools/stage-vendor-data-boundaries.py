#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Separate legacy vendor child-data access from Android17 vold-owned containers.

Preserves media/vendor container traversal and other nonmutation permissions.
Mutation permissions address only the original child-data type. System container
access and file-class access to directory-only vendor containers are excluded.
Current platform/vold grants, labels, encryption and filesystem data are unchanged.
"""
import argparse,hashlib,importlib.util,json
from pathlib import Path
def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.baseline.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
paths=[Path(x['path']) for x in base['inputs'] if Path(x['path']).name=='vendor_sepolicy.cil'];assert len(paths)==1
src=paths[0];texts={};definitions={}
for item in base['inputs']:
 path=Path(item['path']);assert sha(path)==item['sha256'];text=path.read_text();texts[path]=text
 for kind,s,e in forms.statements(text,cil.tokens):
  if kind=='typeattributeset':
   ts=cil.tokens(text[s:e]);definitions.setdefault(ts[2][1],[]).append(ts)
aliases={'media_rw_data_file_30_0':('media_rw_data_file','media_userdir_file'),
 'system_data_file_30_0':('system_data_file','system_userdir_file'),
 'vendor_data_file_30_0':('vendor_data_file','vendor_userdir_file')}
for name,expected in aliases.items():
 defs=definitions[name];assert len(defs)==1
 ts=defs[0];assert ts[3][0]=='(' and ts[-2][0]==')' and {t[1] for t in ts[4:-2]}==set(expected)
groups={old:'vendor_samsung_port_child_'+pair[0] for old,pair in aliases.items()}
for group in groups.values():
 for text in texts.values():assert group not in text
def rule(source,target,cls,perms):return f'(allow {source} {target} ({cls} ('+' '.join(perms)+')))'
original=texts[src];pieces=[];end=0;ledger=[];mutation={'write','add_name','remove_name'}
for kind,start,stop in forms.statements(original,cil.tokens):
 if kind!='allow':continue
 text=original[start:stop];ts=[t[1] for t in cil.tokens(text)]
 source,target=ts[2:4]
 if target not in aliases:continue
 assert ts[4]=='(' and ts[6]=='(' and ts[-3:]==[')',')',')']
 cls=ts[5];perms=ts[7:-3];assert all(x not in ['(',')','and','not','or'] for x in perms)
 after=[]
 if cls=='dir' and target in ['media_rw_data_file_30_0','vendor_data_file_30_0']:
  unchanged=[p for p in perms if p not in mutation];restricted=[p for p in perms if p in mutation]
  if not restricted:continue
  if unchanged:after.append(rule(source,target,cls,unchanged))
  after.append(rule(source,groups[target],cls,restricted))
 elif target=='system_data_file_30_0' or (target=='vendor_data_file_30_0' and cls=='file'):
  after.append(rule(source,groups[target],cls,perms))
 else:continue
 replacement='\n'.join(after)
 pieces.extend([original[end:start],replacement]);end=stop
 ledger.append({'before':text,'after':after,'retained_container_traversal':cls=='dir' and target!='system_data_file_30_0'})
pieces.append(original[end:]);staged=''.join(pieces)
addition='\n'
for old,(child,container) in aliases.items():
 group=groups[old];addition+=f'(typeattribute {group})\n(typeattributeset {group} (and {old} {child}))\n'
staged+=addition
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(src.parent) and not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged);(out/'added-data-scopes.cil').write_text(addition)
root=Path('/srv/android/src/lineage-24.0-arm64/system/sepolicy/private')
report={'scope':__doc__,'current_two_member_api30_aliases':aliases,'changes':ledger,
 'fresh_target_intersections_only':True,'permission_sets_partitioned_without_new_bits':True,
 'platform_vold_rules_labels_fstab_or_data_modified':False,
 'source_files_sha256':{str(f):sha(f) for f in [src,a.baseline,root/'vold.te',root/'file_contexts']},
 'runner_sha256':sha(Path(__file__)),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
 'physical_fbe_or_vendor_hardware_behavior_validated':False,'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');assert src.read_text()==original
print('STAGED data boundary permission partitions:',len(ledger),'; no encryption/label/data changes')
