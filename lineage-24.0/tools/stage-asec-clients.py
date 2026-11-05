#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind two old ASEC grants to ABI-visible frozen app clients and vendor apps.

The original source attribute is retained and intersected with a new positive
legacy client set. Current/private sandbox names are not imported into vendor ABI.
This proves source-set narrowing, not complete runtime access coverage.
"""
import argparse, hashlib, importlib.util, json
from pathlib import Path

def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.baseline.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
vendors=[Path(x['path']) for x in base['inputs'] if Path(x['path']).name=='vendor_sepolicy.cil'];assert len(vendors)==1
src=vendors[0];assert sha(src)=='648a6273d5cefb3491e5df7113d4216a7fd345859d2c9110c5cf2053058a9494'
texts={}
for x in base['inputs']:
 path=Path(x['path']);assert sha(path)==x['sha256'];texts[path]=path.read_text()
root=Path('/srv/android/src/lineage-24.0-arm64')
frozen=root/'out/soong/.intermediates/system/sepolicy/prebuilts/api/30.0/30.0_plat_policy.cil/android_common/30.0_plat_policy.cil'
assert sha(frozen)=='94007d1d20ce24a4f2a74920d82f0fabc2a0718cb61bb5996b7fa7dad64d67e9'
audit_root=Path('/srv/android/artifacts/lineage-24.0-arm64/frozen-policy-oracle-20261105-01')
for phase in ['before','after']:
 audit=json.loads((audit_root/f'source-audit-{phase}.json').read_text())
 assert audit['passed'] and audit['project_count']==1243 and audit['reviewed_patch_count']==15
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(root) and not out.is_relative_to(src.parent)
def members(text,name):
 found=[]
 for kind,start,stop in forms.statements(text,cil.tokens):
  if kind!='typeattributeset':continue
  ts=cil.tokens(text[start:stop])
  if ts[2][1]!=name:continue
  assert ts[3][0]=='(' and ts[-2][0]==')'
  assert all(t[0]=='symbol' and t[1] not in ['and','or','not','all','xor'] for t in ts[4:-2])
  found.append([t[1] for t in ts[4:-2]])
 assert len(found)==1
 return found[0]
declared=set()
for text in texts.values():
 for kind,s,e in forms.statements(text,cil.tokens):
  if kind in ['type','typeattribute']:declared.add(cil.tokens(text[s:e])[2][1])
frozen_apps=members(frozen.read_text(),'appdomain')
mapped={name:name+'_30_0' for name in frozen_apps if name+'_30_0' in declared}
skipped=sorted(set(frozen_apps)-mapped.keys())
vendor_apps=members(texts[src],'appdomain')
assert set(vendor_apps)<=declared
legacy=sorted(set(mapped.values())|set(vendor_apps))
group,subset='vendor_samsung_port_asec_legacy_apps','vendor_samsung_port_asec_clients'
for text in texts.values():assert group not in text and subset not in text
oldsource='base_typeattr_561_30_0'
definitions=[]
for kind,s,e in forms.statements(texts[src],cil.tokens):
 if kind=='typeattributeset' and cil.tokens(texts[src][s:e])[2][1]==oldsource:definitions.append(texts[src][s:e])
assert len(definitions)==1
changes=[];staged=texts[src]
for target in ['asec_apk_file_30_0','asec_public_file_30_0']:
 old=f'(allow {oldsource} {target} (file (getattr map execute execute_no_trans)))'
 new=f'(allow {subset} {target} (file (getattr map execute execute_no_trans)))'
 assert staged.splitlines().count(old)==1;staged=staged.replace(old+'\n',new+'\n')
 changes.append({'before':old,'after':new})
addition=f'\n(typeattribute {group})\n(typeattributeset {group} ('+' '.join(legacy)+'))\n'
addition+=f'(typeattribute {subset})\n(typeattributeset {subset} (and {oldsource} {group}))\n'
staged+=addition
assert cil.rule_counts(staged)==cil.rule_counts(texts[src])
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged);(out/'added-client-scope.cil').write_text(addition)
report={'scope':__doc__,'frozen_appdomains':frozen_apps,'abi_visible_frozen_mapping':mapped,
 'unmapped_frozen_private_clients_not_imported':skipped,'vendor_apps':vendor_apps,'legacy_positive_clients':legacy,
 'changes':changes,'original_source_attribute_unchanged':definitions[0],
 'subset_definition':f'(typeattributeset {subset} (and {oldsource} {group}))',
 'source_intersection_is_subset_by_construction':True,'runtime_or_complete_client_coverage_proved':False,
 'inputs_sha256':{str(frozen):sha(frozen),str(a.baseline):sha(a.baseline),str(src):sha(src),
                  **{str(audit_root/f'source-audit-{phase}.json'):sha(audit_root/f'source-audit-{phase}.json') for phase in ['before','after']}},
 'runner_sha256':sha(Path(__file__)),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
 'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
assert src.read_text()==texts[src]
print('STAGED ASEC source intersection:',len(legacy),'positive clients; skipped private frozen names:',skipped)
