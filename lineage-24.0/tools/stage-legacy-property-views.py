#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bound old public property views to current producer and partition ownership.

Preserves non-core vendor-default readers and core setupwizard readers. Newer
HAL/charger/boot/build-config properties are excluded from broad old grants.
No context, value, owner, assertion or current platform grant is changed.
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
src=paths[0];texts={};declared=set()
for x in base['inputs']:
 path=Path(x['path']);assert sha(path)==x['sha256'];texts[path]=path.read_text()
 for kind,s,e in forms.statements(texts[path],cil.tokens):
  if kind in ['type','typeattribute']:declared.add(cil.tokens(texts[path][s:e])[2][1])
root=Path('/srv/android/src/lineage-24.0-arm64')
frozen=root/'out/soong/.intermediates/system/sepolicy/prebuilts/api/30.0/30.0_plat_policy.cil/android_common/30.0_plat_policy.cil'
assert sha(frozen)=='94007d1d20ce24a4f2a74920d82f0fabc2a0718cb61bb5996b7fa7dad64d67e9'
def members(text,name):
 result=[]
 for k,s,e in forms.statements(text,cil.tokens):
  if k=='typeattributeset':
   ts=cil.tokens(text[s:e])
   if ts[2][1]==name:
    assert ts[3][0]=='(' and ts[-2][0]==')' and all(t[0]=='symbol' for t in ts[4:-2])
    result.append([t[1] for t in ts[4:-2]])
 assert len(result)==1;return result[0]
old_domains=members(frozen.read_text(),'domain')
mapped={n:n+'_30_0' for n in old_domains if n+'_30_0' in declared}
vendor_domains=members(texts[src],'domain');legacy=sorted(set(mapped.values())|set(vendor_domains))
prefix='vendor_samsung_port_prop_api_'
for t in texts.values():assert prefix not in t
addition=f'\n(typeattribute {prefix}noncore)\n(typeattributeset {prefix}noncore (not coredomain))\n'
addition+=f'(typeattribute {prefix}core_readers)\n(typeattributeset {prefix}core_readers (and domain coredomain))\n'
addition+=f'(typeattribute {prefix}legacy_domain_names)\n(typeattributeset {prefix}legacy_domain_names ('+' '.join(legacy)+'))\n'
addition+=f'(typeattribute {prefix}legacy_domains)\n(typeattributeset {prefix}legacy_domains (and domain {prefix}legacy_domain_names))\n'
aux={
 'no_build_config':'(not build_config_prop)',
 'no_charger':'(not charger_status_prop)',
 'vendor_set_excluded':'(system_internal_property_type system_restricted_property_type bootanim_system_prop charger_status_prop)',
 'vendor_settable':f'(not {prefix}vendor_set_excluded)'}
for n,expr in aux.items():addition+=f'(typeattribute {prefix+n})\n(typeattributeset {prefix+n} {expr})\n'
targets={'default_prop_30_0':('default_safe',prefix+'no_build_config'),
 'exported_system_prop_30_0':('exported_system_safe',prefix+'no_charger'),
 'exported_wifi_prop_30_0':('wifi_framework','exported_wifi_prop')}
for old,(n,right) in targets.items():addition+=f'(typeattribute {prefix+n})\n(typeattributeset {prefix+n} (and {old} {right}))\n'
addition+=f'(typeattribute {prefix}vendor_system_set)\n(typeattributeset {prefix}vendor_system_set (and exported_system_prop_30_0 {prefix}vendor_settable))\n'
original=texts[src];pieces=[];end=0;ledger=[];source_groups={}
for kind,start,stop in forms.statements(original,cil.tokens):
 if kind!='allow':continue
 form=original[start:stop];ts=cil.tokens(form);source,target,cls=ts[2][1],ts[3][1],ts[5][1]
 newsource,newtarget=source,target;drop=False
 if target=='setupwizard_prop' and cls=='file':
  if source=='domain':newsource=prefix+'core_readers'
  elif source in ['gpsd','vendor_init_30_0']:drop=True
 elif source=='domain' and target=='vendor_configs_file_30_0' and cls=='file':newsource=prefix+'legacy_domains'
 elif target=='vendor_default_prop_30_0':
  newsource=prefix+'noncore_'+source
  if source not in source_groups:
   addition+=f'(typeattribute {newsource})\n(typeattributeset {newsource} (and {source} {prefix}noncore))\n'
   source_groups[source]=newsource
 elif target=='default_prop_30_0':newtarget=prefix+'default_safe'
 elif target=='exported_wifi_prop_30_0' and cls=='property_service':newtarget=prefix+'wifi_framework'
 elif target=='exported_system_prop_30_0':
  newtarget=prefix+'vendor_system_set' if source=='vendor_init_30_0' and cls=='property_service' else prefix+'exported_system_safe'
 if not drop and newsource==source and newtarget==target:continue
 replacement=form
 if drop:replacement=''
 else:
  for i,value in sorted([(2,newsource),(3,newtarget)],reverse=True):
   token=ts[i];replacement=replacement[:token[2]]+value+replacement[token[3]:]
 pieces.extend([original[end:start],replacement]);end=stop
 ledger.append({'before':form,'after':replacement})
pieces.append(original[end:]);staged=''.join(pieces)+addition
assert any(x['before'].startswith('(allow gpsd setupwizard_prop ') and not x['after'] for x in ledger)
contexts=[Path(base['build_output_root'])/'target/product/gta3xlwifi/system/etc/selinux/plat_property_contexts',
 Path('/srv/android/artifacts/lineage-24.0-arm64/platform-policy-port-20261105-03/metadata/vendor/etc/selinux/vendor_property_contexts')]
query='persist.vendor.camera.privapp.list';matches=[]
for f in contexts:
 for line in f.read_text().splitlines():
  fields=line.partition('#')[0].split()
  if not fields:continue
  assert len(fields)>=2 and fields[1].startswith('u:object_r:')
  key=fields[0];mode=fields[2] if len(fields)>2 and fields[2] in ['exact','prefix'] else 'prefix'
  if (mode=='exact' and query==key) or (mode=='prefix' and (key=='*' or query.startswith(key))):
   matches.append((len(key) if key!='*' else 0,mode=='exact',key,fields[1],str(f)))
assert matches;camera_context=max(matches)
assert camera_context[3]=='u:object_r:vendor_camera_prop:s0'
assert '(allow domain vendor_camera_prop (file (read getattr map open)))' in original
consumer=root/'frameworks/av/services/camera/libcameraservice/api2/CameraDeviceClient.cpp'
assert query in consumer.read_text()
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(src.parent) and not out.is_relative_to(root)
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged);(out/'added-property-views.cil').write_text(addition)
report={'scope':__doc__,'changes':ledger,'legacy_domain_names':legacy,'mapped_frozen_domains':mapped,
 'unmapped_private_frozen_domains_not_imported':sorted(set(old_domains)-mapped.keys()),
 'camera_consumer_property':query,'camera_best_prefix_context':camera_context,
 'camera_existing_typed_read_grant_preserved':True,'property_contexts_or_values_modified':False,
 'inputs_sha256':{str(f):sha(f) for f in [src,a.baseline,frozen,consumer,*contexts]},
 'runner_sha256':sha(Path(__file__)),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
 'complete_runtime_property_coverage_proved':False,'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');assert src.read_text()==original
print('STAGED legacy property/source views:',len(ledger),'; camera typed prefix/read access preserved')
