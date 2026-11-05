#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bound legacy metadata operations away from Android17 protected resources.

Preserves OEM filesystem reads, other proc/debug metadata and legacy device
operations. APEX device names are not imported from private platform policy.
All current platform grants and original assertions/classifications remain.
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
src=paths[0];texts={};types=set();attrs=set();definitions={}
for item in base['inputs']:
 path=Path(item['path']);assert sha(path)==item['sha256'];text=path.read_text();texts[path]=text
 for kind,start,stop in forms.statements(text,cil.tokens):
  ts=cil.tokens(text[start:stop])
  if kind=='type':types.add(ts[2][1])
  elif kind=='typeattribute':attrs.add(ts[2][1])
  elif kind=='typeattributeset':definitions.setdefault(ts[2][1],[]).append(ts)
def members(text,name):
 result=[]
 for kind,start,stop in forms.statements(text,cil.tokens):
  if kind=='typeattributeset':
   ts=cil.tokens(text[start:stop])
   if ts[2][1]==name:
    assert ts[3][0]=='(' and ts[-2][0]==')' and all(t[0]=='symbol' for t in ts[4:-2])
    result.append([t[1] for t in ts[4:-2]])
 assert len(result)==1;return result[0]
root=Path('/srv/android/src/lineage-24.0-arm64')
frozen=root/'out/soong/.intermediates/system/sepolicy/prebuilts/api/30.0/30.0_plat_policy.cil/android_common/30.0_plat_policy.cil'
assert sha(frozen)=='94007d1d20ce24a4f2a74920d82f0fabc2a0718cb61bb5996b7fa7dad64d67e9'
pub=[p for p in texts if p.name=='plat_pub_versioned.cil'];assert len(pub)==1
public_types={cil.tokens(texts[pub[0]][s:e])[2][1] for k,s,e in forms.statements(texts[pub[0]],cil.tokens) if k=='type'}
olddevices=set(members(frozen.read_text(),'dev_type'))&public_types
vendor_devices=set(members(texts[src],'dev_type'))
legacy_devices=sorted((olddevices|vendor_devices)-{'apex_dm_device'})
def positive(name,trail=()):
 if name in types:return {name}
 assert name in attrs and name not in trail,(name,trail)
 result=set()
 for ts in definitions.get(name,[]):
  assert ts[3][0]=='(' and ts[-2][0]==')' and all(t[0]=='symbol' and t[1] not in ['and','or','not','all','xor'] for t in ts[4:-2]),name
  for token in ts[4:-2]:result|=positive(token[1],trail+(name,))
 return result
expanded=set()
for name in legacy_devices:expanded|=positive(name)
assert 'apex_dm_device' not in expanded
prefix='vendor_samsung_port_meta_'
for text in texts.values():assert prefix not in text
scope={
 ('init_30_0','vendor_samsung_port_nonbpf_fs551','file'):('fs551_no_etm','no_etm'),
 ('init_30_0','sysfs_type','file'):('sysfs_no_etm','no_etm'),
 ('dumpstate_30_0','vendor_samsung_port_nonbpf_fs545','file'):('fs545_safe','non_sensitive'),
 ('dumpstate_30_0','base_typeattr_547_30_0','file'):('proc547_safe','non_sensitive'),
 ('dumpstate_30_0','base_typeattr_548_30_0','file'):('debug548_safe','non_sensitive'),
 ('hal_dumpstate_default','base_typeattr_549_30_0','file'):('debug549_safe','non_sensitive'),
 ('system_server_30_0','proc_type','file'):('proc_safe','non_sensitive'),
 ('hal_proca_default','oemfs_30_0','file'):('oem_only','oemfs'),
 ('init_30_0','dev_type','blk_file'):('legacy_devices','device_names')}
original=texts[src];pieces=[];end=0;ledger=[];used={}
for kind,start,stop in forms.statements(original,cil.tokens):
 if kind!='allow':continue
 form=original[start:stop];ts=cil.tokens(form);key=(ts[2][1],ts[3][1],ts[5][1])
 if key not in scope:continue
 name,operand=scope[key];newtarget=prefix+name
 replacement=form[:ts[3][2]]+newtarget+form[ts[3][3]:]
 pieces.extend([original[end:start],replacement]);end=stop
 used[name]=(key[1],operand);ledger.append({'before':form,'after':replacement})
pieces.append(original[end:]);staged=''.join(pieces)
assert set(used)=={n for n,_ in scope.values()}
addition=f'\n(typeattribute {prefix}sensitive)\n(typeattributeset {prefix}sensitive (proc_kallsyms debugfs_kprobes debugfs_tracing_printk_formats))\n'
addition+=f'(typeattribute {prefix}non_sensitive)\n(typeattributeset {prefix}non_sensitive (not {prefix}sensitive))\n'
addition+=f'(typeattribute {prefix}no_etm)\n(typeattributeset {prefix}no_etm (not sysfs_devices_cs_etm))\n'
addition+=f'(typeattribute {prefix}device_names)\n(typeattributeset {prefix}device_names ('+' '.join(legacy_devices)+'))\n'
for name,(old,operand) in used.items():
 right=operand if operand=='oemfs' else prefix+operand
 addition+=f'(typeattribute {prefix+name})\n(typeattributeset {prefix+name} (and {old} {right}))\n'
staged+=addition;assert cil.rule_counts(staged)==cil.rule_counts(original)
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(src.parent) and not out.is_relative_to(root)
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged);(out/'added-metadata-scopes.cil').write_text(addition)
report={'scope':__doc__,'changes':ledger,'frozen_public_device_names':sorted(olddevices),'vendor_device_names':sorted(vendor_devices),
 'positive_device_scope':legacy_devices,'expanded_device_types':sorted(expanded),'apex_private_device_not_in_scope':True,
 'oemfs_original_alias_types':members(texts[next(p for p in texts if p.name=='30.0.cil' and '/system/etc/' in str(p))],'oemfs_30_0'),
 'original_attributes_labels_assertions_changed':False,'new_concrete_types_or_permission_bits':False,
 'inputs_sha256':{str(src):sha(src),str(a.baseline):sha(a.baseline),str(frozen):sha(frozen),str(pub[0]):sha(pub[0])},
 'runner_sha256':sha(Path(__file__)),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
 'runtime_device_or_diagnostic_coverage_proved':False,'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');assert src.read_text()==original
print('STAGED protected-metadata target intersections:',len(ledger),'; legacy devices:',len(legacy_devices))
