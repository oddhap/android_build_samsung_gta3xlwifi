#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retire reviewed all-core-writer grants to vendor-restricted properties.

Every concrete source is a non-init core type and each rule is identified by the actual
Android17 compiler as violating the unchanged non-init core writer assertion.
No source classification, init exception, non-core writer or read grant changes.
"""
import argparse, hashlib, importlib.util, json
from pathlib import Path

PAIRS='''bluetooth_30_0 vendor_bluetooth_prop
cameraserver_30_0 sec_camera_prop
lmkd_30_0 lmk_prop
platform_app_30_0 ccm_prop
radio_30_0 rild_prop
system_app_30_0 apm_prop
system_app_30_0 facm_prop
system_app_30_0 cp_reserved_mem_prop
system_app_30_0 sec_factory_facm_prop
system_app_30_0 vendor_omadm_prop
system_app_30_0 sec_ims_prop
system_app_30_0 vzw_os_prop
system_app_30_0 ina_status_prop
system_app_30_0 sec_camera_prop
system_server_30_0 vendor_model_suffix_prop
system_server_30_0 security_prop
system_server_30_0 ccm_prop
system_server_30_0 apm_prop
system_server_30_0 sec_camera_prop
system_server_30_0 vendor_camera_motor_prop
zygote_30_0 vendor_zygoteinit_prop
policyloader_app security_prop
mediadrmserver_30_0 vendor_mediadrm_prop
mediaserver_30_0 sec_camera_prop
vramdiskd vramdiskd_prop'''
def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.baseline.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
proofpath=a.baseline.parent.parent/'verbose/report.json';proof=json.loads(proofpath.read_text())
assert proof['baseline_report_sha256']==sha(a.baseline) and proof['neverallow_checks_enabled']
paths=[Path(x['path']) for x in base['inputs'] if Path(x['path']).name=='vendor_sepolicy.cil'];assert len(paths)==1
src=paths[0];types=set();attributes=set();definitions={}
for item in base['inputs']:
 path=Path(item['path']);assert sha(path)==item['sha256']==proof['input_sha256'][str(path)]
 text=path.read_text()
 for kind,s,e in forms.statements(text,cil.tokens):
  if kind=='type':types.add(cil.tokens(text[s:e])[2][1])
  elif kind=='typeattribute':attributes.add(cil.tokens(text[s:e])[2][1])
  elif kind=='typeattributeset':
   ts=cil.tokens(text[s:e]);definitions.setdefault(ts[2][1],[]).append(ts)
expected={f'(allow {s} {t} (property_service (set)))' for s,t in (line.split() for line in PAIRS.splitlines())}
assert len(expected)==25
assertion='(neverallow vendor_samsung_port_noninit_core vendor_samsung_port_restricted_properties (property_service (set)))'
records=[c for c in proof['conflicts'] if c['assertion']==assertion];assert len(records)==1
assert {g['statement'] for g in records[0]['matching_grants']}==expected
cache={};witness={}
def positive(name,trail=()):
 if name in types:return {name}
 assert name in attributes and name not in trail,(name,trail)
 if name in cache:return cache[name]
 result=set()
 for ts in definitions.get(name,[]):
  assert ts[3][0]=='(' and ts[-2][0]==')'
  assert all(t[0]=='symbol' and t[1] not in ['and','or','not','xor','all'] for t in ts[4:-2]),name
  witness.setdefault(name,[]).append(' '.join(t[1] for t in ts))
  for token in ts[4:-2]:result|=positive(token[1],trail+(name,))
 cache[name]=result;return result
core=positive('coredomain')-{'init'};concrete_sources={}
for line in PAIRS.splitlines():
 source=line.split()[0]
 concrete=positive(source);assert concrete and concrete<=core,(source,concrete-core)
 concrete_sources[source]=sorted(concrete)
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(src.parent) and not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
original=src.read_text();staged=original
for statement in sorted(expected):
 assert staged.splitlines().count(statement)==1
 staged=staged.replace(statement+'\n','\n')
before,after=cil.rule_counts(original),cil.rule_counts(staged);assert after==dict(before,allow=before['allow']-25)
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged)
report={'scope':__doc__,'removed_grants':sorted(expected),'concrete_core_sources':concrete_sources,
 'positive_membership_witness':witness,
 'actual_compiler_assertion':assertion,'assertions_and_attribute_definitions_changed':False,
 'allow_permissions_added':False,'vendor_rules_before':before,'vendor_rules_after':after,
 'inputs_sha256':{str(a.baseline):sha(a.baseline),str(proofpath):sha(proofpath),str(src):sha(src)},
 'runner_sha256':sha(Path(__file__)),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
 'runtime_feature_compatibility_proved':False,'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');assert src.read_text()==original
print('STAGED: 25 reviewed forbidden core-writer grants removed; init/non-core writers and read grants unchanged')
