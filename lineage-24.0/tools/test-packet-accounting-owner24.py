#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual packet-accounting primitive admission and shared four-state policy owner.

Reuses bound full-owner and factory/formatter table fixtures. Exercises every
startup/update I/O failure, primitive absence, quotas, drift and recovery. Real
kernel rules, UID accounting, platform service startup and Ready are not claimed.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','projection-host','accounting-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();P=a.projection_host.resolve();A=a.accounting_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for base in [P,A]:
 r=json.loads((base/'report.json').read_text());assert r['passed'] and sha(base/'test.cpp')==r['inputs_sha256'][str(base/'test.cpp')]
shutil.copyfile(P/'IptablesRestoreController.h',O/'IptablesRestoreController.h');code=(P/'test.cpp').read_text().split('int main(){',1)[0]
fixture=(A/'test.cpp').read_text();fixture=fixture[fixture.index('static const std::vector<std::string> program='):fixture.index('int main(){')]
for old,new in [('Table','AccountingTable'),('Tables','AccountingTables'),('Rules','AccountingRules'),('Model','AccountingModel'),('expected','expectedAccounting'),('canonicalRule','accountingCanonical')]:fixture=re.sub(r'\b'+old+r'\b',new,fixture)
fixture=fixture.replace('static void resetAccounting(){resetEvents();features=4095;}','');code+='\n'+fixture+r'''
struct AccountingCombined:Combined{
 AccountingModel accounting;bool driftOnPolicyWrite=false;
 AccountingCombined(){for(unsigned f=0;f<2;++f)for(const auto&[n,r]:accounting.tables[f][0].chains)filter.tables[f].chains[n]=r;}
 int execute(IptablesTarget family,const std::string&command,std::string*out)override{
  if(command.rfind("*raw\n",0)==0||command.rfind("*mangle\n",0)==0){assert(firewallAllowed);++calls;bool bad=point();if(bad&&!ioAfter)return -1;int result=accounting.execute(family,command,out);return bad?-1:result;}
  int result=Combined::execute(family,accountingCanonical(command),out);
  if(driftOnPolicyWrite&&command.rfind("*g24sock\n:",0)==0){accounting.tables[1][2].chains["bw_mangle_POSTROUTING"].pop_back();driftOnPolicyWrite=false;}
  return result;
 }
};
static void resetIntegrated(){resetProjection();features=16383;}
int main(){unsigned startPoints=0,replacePoints=0;
 auto state=desired();auto other=desired(110001);auto invalid=program;invalid.push_back("*filter");
 resetIntegrated();{AccountingCombined k;P p(k);C(p.startWithAccounting(invalid)==-EINVAL&&opens==0&&ioCount==0);C(p.startWithAccounting(program)==0&&held&&opens==1);startPoints=ioCount;P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);ioCount=0;C(p.replace(state,0)==0&&!held&&opens==1&&files.size()==1);replacePoints=ioCount;checkState(p,10001,1);auto before=ioCount;C(p.startWithAccounting(program)==-EALREADY&&ioCount==before&&!held);C(p.setDataSaver(false)==0&&!held);C(p.snapshot(&out,&g)==0&&g==2&&!out.policy.dataSaver());
  k.filter.tables[0].chains["bw_INPUT"].insert(k.filter.tables[0].chains["bw_INPUT"].begin(),"-A bw_INPUT -i wlan0 -j bw_costly_shared");auto quota=k.filter.tables[0].chains["bw_INPUT"];C(p.setDataSaver(true)==0&&k.filter.tables[0].chains["bw_INPUT"]==quota&&!held);
  k.accounting.tables[1][2].chains["bw_mangle_POSTROUTING"].pop_back();C(p.setDataSaver(false)==-EPROTO&&held&&files.empty());C(p.snapshot(&out,&g)==-EAGAIN);
 }
 for(unsigned bit=0;bit<14;++bit){resetIntegrated();features=16383^(1u<<bit);AccountingCombined k;P p(k);C(p.startWithAccounting(program)==-EOPNOTSUPP&&held&&files.empty()&&k.calls==0);}
 for(bool after:{false,true})for(unsigned point=1;point<=startPoints;++point){resetIntegrated();AccountingCombined k;P p(k);ioFault=point;ioAfter=after;C(p.startWithAccounting(program)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 for(bool after:{false,true})for(unsigned point=1;point<=replacePoints;++point){resetIntegrated();AccountingCombined k;P p(k);C(p.startWithAccounting(program)==0);ioCount=0;ioFault=point;ioAfter=after;C(p.replace(state,0)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.replace(other,0)==-ENOTCONN);}
 resetIntegrated();{AccountingCombined k;for(auto&f:k.hooks)for(auto&[n,r]:f){(void)n;r.clear();}P p(k);C(p.startWithAccounting(program,P::HookMode::InstallMissing)==0&&held);C(p.replace(state,0)==0&&!held&&opens==1);}
 for(unsigned point:{startPoints/2,startPoints-2}){resetIntegrated();AccountingCombined k;P p(k);ioFault=point;ioAfter=true;C(p.startWithAccounting(program)<0&&held&&files.empty());ioFault=0;C(p.startWithAccounting(program)==0&&held);C(p.replace(state,0)==0&&!held);}
 resetIntegrated();{AccountingCombined k;k.accounting.tables[1][2].chains["bw_mangle_POSTROUTING"]={"-A bw_mangle_POSTROUTING -m bpf --object-pinned /old"};P p(k);C(p.startWithAccounting(program)==-EPROTO&&k.filter.writes==0&&k.accounting.writes==0&&held&&files.empty());}
 resetIntegrated();{AccountingCombined k;P p(k);C(p.startWithAccounting(program)==0);k.driftOnPolicyWrite=true;C(p.replace(state,0)==-EPROTO&&held&&files.empty()&&lnaSets==0&&setCalls==0);P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==-EAGAIN);}
 resetIntegrated();{AccountingCombined k;k.denyControl=true;P p(k);auto root=state;assert(root.permissions.set(0,4)==0);C(p.startWithAccounting(program)==0&&p.replace(root,0)==0&&!held);C(p.setDataSaver(false)<0&&held&&files.empty()&&kernelImage.front().uid==0&&kernelImage.front().permissions==4);}
 C(files.empty()&&held);printf("passed_cases=%u start_fault_points=%u replace_fault_points=%u\n",cases,startPoints,replacePoints);
}
'''
marker=code.index('static const std::vector<std::string> program=');code=code[:marker]+re.sub(r'\bprogram\b','accountingProgram',code[marker:])
(O/'test.cpp').write_text(code);names=['Gta3xlwifiNetpolicyLease','Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiSocketRoots','Gta3xlwifiIngressPolicy','Gta3xlwifiMeteredChainProgram','Gta3xlwifiMeteredRoots','Gta3xlwifiUidPermissionState','Gta3xlwifiLocalNetworkState','Gta3xlwifiSocketPolicyProjection','Gta3xlwifiAccountingRoots'];sources=[S/(n+'.cpp') for n in names]
cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+n for n in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=120,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.fullmatch(r'passed_cases=(\d+) start_fault_points=(\d+) replace_fault_points=(\d+)\n',x.stdout);assert m and int(m[1])>=300
paths=[Path(__file__),P/'report.json',P/'test.cpp',A/'report.json',A/'test.cpp',O/'test.cpp',O/'IptablesRestoreController.h',S/'projection-guards.inc',*sources,*[p.with_suffix('.h') for p in sources],*[p for p in (S/'linux/netfilter').glob('*.h')]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'start_fault_points':int(m[2]),'replace_fault_points':int(m[3]),'one_lease_four_state_publication':True,'hard_no_firewall_after_first_image_set':True,'actual_accounting_startup_and_reverification':True,'packet_storage_and_compiled_hooks_required_before_firewall':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'rules_installed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
