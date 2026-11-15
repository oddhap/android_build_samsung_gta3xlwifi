#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual owner regression replay with explicitly changed held-counterset admission.

Verified producers may accept real UID counterset metadata before publication;
all reads, SWAP/ACK and traffic remain held until the complete policy is committed.
"""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==26321
for n,h in r['inputs_sha256'].items():assert sha(Path(n))==h
for n in ['binder','com']:shutil.copytree(R/n,O/n)
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
code=(R/'test.cpp').read_text();old='for(unsigned op=0;op<7;op++)C(operation(p,op,o)==-EAGAIN&&packetCalls==0&&o.unchanged()&&held);';assert code.count(old)==1
code=code.replace(old,'for(unsigned op=0;op<7;op++){auto before=packetCalls;int result=operation(p,op,o);C(op==5 ? (result==0&&packetCalls==before+1) : (result==-EAGAIN&&packetCalls==before));C(o.unchanged()&&held);}')
old='C(service->setStatsCounterset(session,123,1).code==EAGAIN);';assert code.count(old)==1;code=code.replace(old,'C(service->setStatsCounterset(session,123,1).isOk()&&held);')
old='int main(int argc,char**argv)';assert code.count(old)==1;code=code.replace(old,'static int previous_held_counterset_tests(int argc,char**argv)')
code+=r'''
int main(int argc,char**argv){C(!previous_held_counterset_tests(argc,argv));unsigned begin=cases;
 resetNames();{AccountingCombined kernel;P owner(kernel);uint64_t generation=99;C(owner.setPacketCounterset(123,1)==-EAGAIN&&held&&files.empty());C(!owner.startWithAccounting(accountingProgram)&&held&&files.size()==1);C(!owner.setPacketCounterset(123,1)&&held&&files.size()==1);C(!owner.frameworkGeneration(&generation)&&generation==0);NetpolicyLease::PacketState state;C(owner.readPacketState(&state)==-EAGAIN&&held);C(!owner.setPacketCounterset(123,0)&&held);C(owner.setPacketCounterset(-1,0)==-EINVAL&&held);C(owner.setPacketCounterset(123,2)==-EINVAL&&held);C(!owner.replace(desired(),0)&&!held);owner.stop();C(owner.setPacketCounterset(123,1)==-EAGAIN&&held&&files.empty());}
 printf("held_counterset_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);oldsource=next(Path(v).parent for v in r['commands'][0] if v.endswith('/Gta3xlwifiSocketPolicyProjection.cpp'));cmd=[v.replace(str(R),str(O)).replace(str(oldsource),str(S)) for v in r['commands'][0]]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test'),str(O/'names-wire.txt')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'held_counterset_cases=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
inputs=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',*[p for p in S.rglob('*') if p.is_file()]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[2]),'new_held_counterset_cases':int(m[1]),'prior_admission_checks_explicitly_updated':2,'HOLD_and_generation_zero_preserved':True,'inputs_sha256':{str(p):sha(p) for p in inputs},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
