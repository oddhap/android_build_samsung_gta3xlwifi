#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare complete strict assertion inventories against the prior explicit policy.

Exact CIL assertion tokens are mandatory here; this is not a claim that arbitrary
attribute definitions or Android runtime behavior are equivalent. Both policies
must pass real strict compilation, with all input hashes bound and no overrides
in the newly composed policy. No policy input substitution is performed.
"""
import argparse,hashlib,importlib.util,json
from collections import Counter
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','candidate','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
kinds={'neverallow','neverallowx','neverallowxperm','constrain','mlsconstrain','validatetrans','mlsvalidatetrans'}
def inventory(path):
 r=json.loads(path.read_text());assert r['passed_strict'] and r['results'][0]['neverallow_checks_enabled'] and '-N' not in r['results'][0]['command']
 found=Counter();permissive=[]
 for x in r['inputs']:
  f=Path(x['path']);assert sha(f)==x['sha256'];text=f.read_text()
  for kind,start,end in forms.statements(text,cil.tokens):
   key=' '.join(t[1] for t in cil.tokens(text[start:end]))
   if kind in kinds:found[key]+=1
   if kind=='typepermissive':permissive.append(key)
 assert found and not permissive
 return r,found
old,A=inventory(a.baseline);new,B=inventory(a.candidate);assert not new['explicit_input_overrides']
removed=A-B;added=B-A
report={'passed':not removed and not added,'baseline_report_sha256':sha(a.baseline),'candidate_report_sha256':sha(a.candidate),'baseline_assertions_and_constraints':sum(A.values()),'candidate_assertions_and_constraints':sum(B.values()),'removed':dict(removed),'added':dict(added),'permissive_domains':[],'new_platform_input_overrides':False,'attribute_semantic_equivalence_claimed':False,'hardware_tested':False,'flash_ready':False}
a.output.write_text(json.dumps(report,indent=2)+'\n');assert report['passed'],report
print('PASS:',sum(B.values()),'exact assertion/constraint records retained; strict compile and enforcing domains')
