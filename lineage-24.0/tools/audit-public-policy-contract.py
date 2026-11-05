#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate an audit-only current public-policy contract with official Soong steps.

Does not substitute any compiler input, change neverallows, compile an alternate
runtime policy or modify a vendor image. Missing required legacy symbols block
an automatic replacement; this is not security/compatibility approval.
"""
import argparse,hashlib,importlib.util,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','baseline-report','vendor','source-audit','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();a.top=a.top.resolve();a.output=a.output.resolve()
assert not a.output.exists() and not a.output.is_relative_to(a.top) and not a.output.is_relative_to(a.vendor.resolve())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base_report=json.loads(a.baseline_report.read_text());assert not base_report['passed_strict']
base_out=a.top/'out-policy-user-20261101-01';pub=base_out/'soong/.intermediates/system/sepolicy/pub_policy.cil/android_common/gta3xlwifi/pub_policy.cil'
version=base_out/'host/linux-x86/bin/version_policy';filter_tool=base_out/'host/linux-x86/bin/build_sepolicy'
spec=importlib.util.spec_from_file_location('cil_tokens',Path(__file__).with_name('stage-vendor-uwb-namespace.py'));cil=importlib.util.module_from_spec(spec);spec.loader.exec_module(cil)
old=a.vendor/'etc/selinux/plat_pub_versioned.cil';vendor=a.vendor/'etc/selinux/vendor_sepolicy.cil'
a.output.mkdir();(a.output/'AUDIT_ONLY_NOT_A_POLICY_REPLACEMENT.txt').write_text('Generated contract analysis only. No compiler/ROM/image inputs replaced and no security or compatibility approval.\n')
mapping=a.output/'identity-mapping.cil';attributed=a.output/'attributed.cil';generated=a.output/'AUDIT_ONLY_current-public-api30.cil'
commands=[[str(version),'-b',str(pub),'-n','30.0','-o',str(mapping),'-m'],[str(version),'-b',str(pub),'-n','30.0','-t',str(pub),'-o',str(attributed)],[str(filter_tool),'filter_out','-f',str(mapping),'-t',str(attributed)]]
for i,command in enumerate(commands):
 r=subprocess.run(command,capture_output=True,text=True);(a.output/f'generator-{i}.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
generated.write_bytes(mapping.read_bytes()+attributed.read_bytes())
def declarations(text):
 ts=cil.tokens(text);result=set()
 for i in range(len(ts)-3):
  if ts[i][0]=='(' and ts[i+1][1] in ['type','typeattribute','typealias'] and ts[i+2][0]=='symbol':result.add(ts[i+2][1])
 return result
oldtext=old.read_text();newtext=generated.read_text();legacy=declarations(oldtext);new=declarations(newtext);vendor_tokens={v for kind,v,_,_ in cil.tokens(vendor.read_text()) if kind=='symbol'}
required=legacy&vendor_tokens;universe=set(new)|declarations(vendor.read_text());policy_inputs=[]
for item in base_report['inputs']:
 path=Path(item['path'])
 if path.name in ['plat_pub_versioned.cil','vendor_sepolicy.cil']:continue
 assert sha(path)==item['sha256'],path;universe|=declarations(path.read_text());policy_inputs.append(path)
missing=sorted(required-universe)
summary={'scope':__doc__,'official_generation_steps_reproduced':True,'requested_version':'30.0','old_public_declaration_count':len(legacy),'generated_public_declaration_count':len(new),'legacy_public_symbols_used_by_vendor':len(required),'required_legacy_symbols_absent_from_generated_plus_current_inputs':missing,'automatic_replacement_blocked':bool(missing),'old_rule_counts':cil.rule_counts(oldtext),'generated_rule_counts':cil.rule_counts(newtext),'original_compiler_inputs_replaced':False,'alternate_combined_policy_compiled':False,'old_neverallow_sources_modified':False,'strict_policy_passed':False,'security_approved':False,'flash_ready':False,'commands':commands,'source_revisions':{str(d):subprocess.check_output(['git','-C',str(d),'rev-parse','HEAD'],text=True).strip() for d in [a.top/'system/sepolicy',a.top/'external/selinux']},'inputs_sha256':{str(f):sha(f) for f in [pub,old,vendor,version,filter_tool,a.baseline_report,a.source_audit,a.top/'system/sepolicy/Android.bp',a.top/'system/sepolicy/build/soong/versioned_policy.go',Path(__file__),Path(__file__).with_name('stage-vendor-uwb-namespace.py'),*policy_inputs]},'generated_contract_sha256':sha(generated),'references':['https://source.android.com/docs/security/features/selinux/build','https://source.android.com/docs/security/features/selinux/compatibility']}
(a.output/'report.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({k:v for k,v in summary.items() if k not in ['commands','inputs_sha256','source_revisions','references','scope']},indent=2))
