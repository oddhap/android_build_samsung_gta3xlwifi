#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual same-owner active stats counts plus complete prior owner regression.

Stats packets/ioctl/kernel state are fixtures here; actual kernel active read and
concurrent updates are validated separately. No tagging authorization or Ready.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==3186 and sha(R/'test.cpp')==r['inputs_sha256'][str(R/'test.cpp')]
for name in ['Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiSocketPolicyProjection.cpp']:assert (S/name).read_bytes().startswith((B/name).read_bytes())
code=(R/'test.cpp').read_text().replace('int main(){','static int controller_regressions(){',1).replace('extern "C" int __wrap_ioctl(', 'extern "C" int activeUnderlyingIoctl(',1)
code+=r'''
static unsigned activeFault,activeRetries,activeCalls;static bool budgetFixture;
static std::vector<gta3xlwifi_packet_stats_entry> activeEntries;
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
 va_list args;va_start(args,cmd);unsigned long arg=va_arg(args,unsigned long);va_end(args);
 if(cmd==GTA3XLWIFI_STATS_GET_STATE&&budgetFixture){bool fail=point();if(fail&&!ioAfter){errno=EIO;return -1;}int result=activeUnderlyingIoctl(fd,cmd,arg);if(fail){errno=EIO;return -1;}return result;}
 if(cmd!=GTA3XLWIFI_STATS_READ||reinterpret_cast<gta3xlwifi_packet_stats_transfer*>(arg)->kind!=GTA3XLWIFI_STATS_ACTIVE)return activeUnderlyingIoctl(fd,cmd,arg);
 assert(files.count(fd)&&!held&&arg);++activeCalls;bool fail=point();if(fail&&!ioAfter){errno=EIO;return -1;}
 auto*t=reinterpret_cast<gta3xlwifi_packet_stats_transfer*>(arg);assert(t->version==1&&t->kind==3&&t->epoch==1&&t->count==5000&&t->entries&&!t->reserved&&!t->lost_updates&&!t->sequence);
 auto*rows=reinterpret_cast<gta3xlwifi_packet_stats_entry*>(uintptr_t(t->entries));std::copy(activeEntries.begin(),activeEntries.end(),rows);t->count=activeEntries.size();t->sequence=77;t->lost_updates=9;
 switch(activeFault){case 0:break;case 1:t->version=2;break;case 2:t->kind=1;break;case 3:++t->epoch;break;case 4:t->reserved=1;break;case 5:t->count=5001;break;case 6:++t->entries;break;case 7:rows[0].key.counterset=2;break;case 8:rows[1].key=rows[0].key;break;case 9:std::swap(rows[0],rows[2]);break;default:assert(false);}
 if(activeRetries){--activeRetries;errno=EINTR;return -1;}if(fail){errno=EIO;return -1;}return 0;
}
static void resetActive(){resetApi();budgetFixture=true;features=65535;activeFault=activeRetries=activeCalls=0;activeEntries={{{1,0,0,17},1,2,3,4},{{1,7,1,17},5,6,7,8},{{5,0,0,18},9,10,11,12}};}
int main(){
 C(controller_regressions()==0);unsigned begin=cases,points=0;
 resetActive();{AccountingCombined k;P p(k);P::TaggingBudget out;out.totalEntries=99;C(p.readTaggingBudget(-1,&out)==-EINVAL&&p.readTaggingBudget(1,nullptr)==-EINVAL&&ioCount==0);C(p.readTaggingBudget(1,&out)==-EAGAIN&&out.totalEntries==99&&ioCount==0);C(p.startWithAccounting(accountingProgram)==0);C(p.readTaggingBudget(1,&out)==-EAGAIN&&held);C(p.replace(desired(),0)==0);ioCount=0;C(p.readTaggingBudget(1,&out)==0&&out.totalEntries==3&&out.uidEntries==2&&out.epoch==1&&out.sequence==77&&out.lostUpdates==9&&!held&&opens==1);points=ioCount;C(p.readTaggingBudget(5,&out)==0&&out.uidEntries==1&&out.totalEntries==3);C(p.readTaggingBudget(10001,&out)==0&&!out.uidEntries&&out.totalEntries==3);activeEntries.clear();C(p.readTaggingBudget(1,&out)==0&&!out.totalEntries&&!out.uidEntries&&out.lostUpdates==9);}
 for(unsigned f=1;f<=9;f++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);P::TaggingBudget out;out.totalEntries=99;activeFault=f;C(p.readTaggingBudget(1,&out)==-EPROTO&&out.totalEntries==99&&held&&files.empty());P::State state;uint64_t g=77;C(p.snapshot(&state,&g)==-EAGAIN&&g==77);}
 for(bool after:{false,true})for(unsigned i=1;i<=points;i++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);ioCount=0;ioFault=i;ioAfter=after;P::TaggingBudget out;out.totalEntries=99;C(p.readTaggingBudget(1,&out)<0&&out.totalEntries==99&&held&&files.empty());}
 resetActive();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);features=32767;P::TaggingBudget out;out.totalEntries=99;C(p.readTaggingBudget(1,&out)==-EOPNOTSUPP&&out.totalEntries==99&&held&&files.empty()&&!activeCalls);}
 resetActive();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);activeRetries=3;P::TaggingBudget out;C(p.readTaggingBudget(1,&out)==0&&activeCalls==4&&!activeRetries&&out.uidEntries==2&&!held);}
 resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(desired(),0)==0);P::TaggingBudget out;auto count=ioCount;C(p.readTaggingBudget(1,&out)==-EOPNOTSUPP&&ioCount==count&&!held);}
 C(points>=5&&files.empty()&&held);printf("active_owner_cases=%u budget_fault_points=%u total_cases=%u\n",cases-begin,points,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h');cmd=[x.replace(str(R),str(O)).replace(str(B),str(S)) for x in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=240,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.search(r'active_owner_cases=(\d+) budget_fault_points=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
paths=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',O/'IptablesRestoreController.h',S/'projection-guards.inc',*S.glob('Gta3xlwifi*.cpp'),*S.glob('Gta3xlwifi*.h'),*(S/'linux/netfilter').glob('*.h')]
d={k:v for k,v in r.items() if k not in ['scope','passed_cases','inputs_sha256','command']};d.update(passed=True,scope=__doc__,passed_cases=int(m[3]),active_owner_cases=int(m[1]),budget_fault_points=int(m[2]),inputs_sha256={str(p):sha(p) for p in paths},command=cmd,stderr=x.stderr)
(O/'report.json').write_text(json.dumps(d,indent=2)+'\n');print(x.stdout.strip())
