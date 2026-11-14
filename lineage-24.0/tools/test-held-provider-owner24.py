#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual held provider verification and complete authorization/owner regression.

Uses real owner/lease code with explicit syscall/rule/tagging fixtures. No real
provider registration, packets or global networking readiness is claimed.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=json.loads((R/'report.json').read_text());assert r['passed'] and r['primary_A17_authorization_comparisons']==7680 and sha(R/'test.cpp')==r['inputs_sha256'][str(R/'test.cpp')]
assert (S/'Gta3xlwifiSocketPolicyProjection.cpp').read_bytes().startswith((B/'Gta3xlwifiSocketPolicyProjection.cpp').read_bytes())
code='static bool allowHeldActive=false;\n'+(R/'test.cpp').read_text().replace('int main(){','static int tagging_regressions(){',1).replace('assert(files.count(fd)&&!held&&arg);','assert(files.count(fd)&&(!held||allowHeldActive)&&arg);',1)
code+=r'''
int main(){
 C(tagging_regressions()==0);unsigned begin=cases,verifyPoints=0;allowHeldActive=true;
 resetActive();{AccountingCombined k;P p(k);C(p.verifyHeldProviderStartup()==-ENOTCONN&&ioCount==0);C(p.prepareForControllerStartup()==0);auto before=ioCount;C(p.verifyHeldProviderStartup()==-ENOTCONN&&ioCount==before&&held);C(p.startWithAccounting(accountingProgram)==0);ioCount=0;C(p.verifyHeldProviderStartup()==0&&held&&opens==1);verifyPoints=ioCount;P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.verifyHeldProviderStartup()==0&&held&&opens==1);C(p.replace(desired(),0)==0);before=ioCount;C(p.verifyHeldProviderStartup()==-EALREADY&&ioCount==before&&!held);}
 for(bool after:{false,true})for(unsigned point=1;point<=verifyPoints;point++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);ioCount=0;ioFault=point;ioAfter=after;C(p.verifyHeldProviderStartup()<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);auto count=ioCount;C(p.verifyHeldProviderStartup()==-ENOTCONN&&ioCount==count);}
 for(unsigned bit=0;bit<16;bit++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);features=65535^(1u<<bit);C(p.verifyHeldProviderStartup()==-EOPNOTSUPP&&held&&files.empty());}
 for(unsigned fault=1;fault<=9;fault++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);activeFault=fault;C(p.verifyHeldProviderStartup()==-EPROTO&&held&&files.empty());}
 resetActive();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);held=false;auto before=k.calls;C(p.verifyHeldProviderStartup()==-EBUSY&&held&&files.empty()&&k.calls==before);}
 resetProjection();{Combined k;P p(k);C(p.start()==0);auto before=ioCount;C(p.verifyHeldProviderStartup()==-EOPNOTSUPP&&ioCount==before&&held);}
 C(files.empty()&&held&&verifyPoints>30);printf("held_provider_owner_cases=%u verification_fault_points=%u total_cases=%u\n",cases-begin,verifyPoints,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h');cmd=[v.replace(str(R),str(O)).replace(str(B),str(S)) for v in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.search(r'held_provider_owner_cases=(\d+) verification_fault_points=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
paths=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',O/'IptablesRestoreController.h',S/'projection-guards.inc',*S.glob('Gta3xlwifi*.h'),*[Path(v) for v in cmd if v.startswith(str(S)) and v.endswith('.cpp')],*(S/'linux/netfilter').glob('*.h')]
d={k:v for k,v in r.items() if k not in ['scope','passed_cases','inputs_sha256','command']};d.update(passed=True,scope=__doc__,passed_cases=int(m[3]),held_provider_owner_cases=int(m[1]),verification_fault_points=int(m[2]),held_provider_keeps_policy_unpublished=True,inputs_sha256={str(p):sha(p) for p in paths},command=cmd,stderr=x.stderr)
(O/'report.json').write_text(json.dumps(d,indent=2)+'\n');print(x.stdout.strip())
