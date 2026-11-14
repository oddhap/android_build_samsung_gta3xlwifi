#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay the actual five-state owner with pre-Controllers lease acquisition.

Real owner/transport code with prior syscall/firewall fixtures, not device proof.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();prior=json.loads((R/'report.json').read_text());assert prior['passed'] and prior['passed_cases']==2711 and sha(R/'test.cpp')==prior['inputs_sha256'][str(R/'test.cpp')]
code=(R/'test.cpp').read_text().replace('int main(){','static int runtime_regressions(){',1)
code+=r'''
int main(){
 C(runtime_regressions()==0);const unsigned before=cases;unsigned preparePoints=0,finishPoints=0;
 resetApi();{AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==0&&held&&opens==1&&files.size()==1&&k.calls==0);preparePoints=ioCount;auto count=ioCount;C(p.prepareForControllerStartup()==-EALREADY&&p.start()==-EBUSY&&ioCount==count&&k.calls==0);P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.replace(desired(),0)==-ENOTCONN&&ioCount==count);auto invalid=accountingProgram;invalid[0]="*raw";C(p.startWithAccounting(invalid)==-EINVAL&&ioCount==count&&held&&opens==1);ioCount=0;C(p.startWithAccounting(accountingProgram)==0&&held&&opens==1);finishPoints=ioCount;C(p.replace(desired(),0)==0&&!held&&opens==1);C(p.prepareForControllerStartup()==-EALREADY);}
 for(unsigned bit=0;bit<15;++bit){resetApi();features=32767^(1u<<bit);AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==-EOPNOTSUPP&&held&&files.empty()&&k.calls==0);}
 for(bool after:{false,true})for(unsigned point=1;point<=preparePoints;++point){resetApi();AccountingCombined k;P p(k);ioFault=point;ioAfter=after;C(p.prepareForControllerStartup()<0&&held&&files.empty()&&k.calls==0);P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 for(bool after:{false,true})for(unsigned point=1;point<=finishPoints;++point){resetApi();AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==0);ioCount=0;ioFault=point;ioAfter=after;C(p.startWithAccounting(accountingProgram)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 resetApi();{AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==0);held=false;auto count=k.calls;C(p.startWithAccounting(accountingProgram)==-EBUSY&&held&&files.empty()&&k.calls==count);}
 resetApi();{AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==0);p.stop();C(held&&files.empty());C(p.prepareForControllerStartup()==0&&opens==1&&held);p.stop();C(held&&files.empty());}
 C(preparePoints>0&&finishPoints>60);printf("controller_owner_cases=%u prepare_fault_points=%u finish_fault_points=%u total_cases=%u\n",cases-before,preparePoints,finishPoints,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
cmd=[x.replace(str(R),str(O)).replace('/srv/android/ports/lineage-24.0-arm64/runtime-owner24-20261114-01',str(S)) for x in prior['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=240,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.search(r'controller_owner_cases=(\d+) prepare_fault_points=(\d+) finish_fault_points=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
paths=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',O/'IptablesRestoreController.h',S/'projection-guards.inc',*S.glob('Gta3xlwifi*.cpp'),*S.glob('Gta3xlwifi*.h'),*(S/'linux/netfilter').glob('*.h')]
d={k:v for k,v in prior.items() if k not in ['inputs_sha256','command','passed_cases','scope']};d.update(passed=True,scope=__doc__,passed_cases=int(m[4]),controller_owner_cases=int(m[1]),prepare_fault_points=int(m[2]),finish_fault_points=int(m[3]),inputs_sha256={str(p):sha(p) for p in paths},command=cmd,stderr=x.stderr)
(O/'report.json').write_text(json.dumps(d,indent=2)+'\n');print(x.stdout.strip())
