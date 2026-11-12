#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real dual-stack private-root bootstrap with syscall/table fault fixtures.

Real lease and checked chain C++ are compiled. Device, credentials, iptables and
kernel lifecycle are models; this is not packet/hardware or backend readiness.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-uid-permission-transport24.py')
subprocess.run(['python3',str(helper),'--source',str(S),'--output',str(O/'uid-regression')],check=True)
checked=Path(__file__).with_name('test-socket-chain-io24.py')
subprocess.run(['python3',str(checked),'--source',str(S),'--output',str(O/'chain-regression')],check=True)
shutil.copyfile(O/'chain-regression/IptablesRestoreController.h',O/'IptablesRestoreController.h')
code=(O/'uid-regression/test.cpp').read_text().split('int main(){',1)[0]
code+=r'''
#include "Gta3xlwifiSocketRoots.h"
#include "Gta3xlwifiOrdinaryDispatch.h"
#include <sstream>
#include <map>
#include <array>
using namespace android::net::gta3xlwifi;
using ChainIO=CheckedUidChains;using RootImage=SocketRoots::Image;
std::vector<std::string> allNames(){std::vector<std::string> n;for(int i=1;i<=9;i++)n.push_back("g24_uid_"+std::to_string(i));n.push_back("g24_owner_in");n.push_back("g24_owner_out");return n;}
RootImage program(){UidPolicy p;assert(p.setChainEnabled(1,true)==0&&p.setUidRule(1,10001,UidPolicy::Allow)==0);RootImage v;assert(UidChainProgram::ordinary(p,&v)==0&&OrdinaryDispatch::append(&v)==0);return v;}
std::string ruleText(const ChainIO::Chain&c,const ChainIO::Rule&r){
 using X=ChainIO;std::string s="-A "+c.name;
 if(r.selector==X::Selector::OwnerSkip)s+=" -m gta3xlwifi_owner_skip";
 else if(r.selector==X::Selector::NonLoopback)s+=" -m gta3xlwifi_non_loopback";
 else if(r.uid){assert(r.selector==X::Selector::RawUid||r.selector==X::Selector::RawAppId);s+=r.selector==X::Selector::RawUid?" -m gta3xlwifi_raw_uid --raw_uid ":" -m gta3xlwifi_raw_appid --raw_appid ";s+=std::to_string(r.uid->first)+":"+std::to_string(r.uid->last);}
 if(r.verdict==X::Verdict::Return)s+=" -j RETURN";
 else if(r.verdict==X::Verdict::Drop)s+=" -j DROP";
 else{assert(r.verdict==X::Verdict::UidCall);s+=" -j g24_uid_"+std::to_string(r.targetUidChain);}return s;
}
struct Tables:IptablesRestoreInterface{
 struct Table{std::array<std::string,2> policy={"DROP","DROP"};std::array<std::vector<std::string>,2> root;std::map<std::string,std::vector<std::string>> chains;};
 std::array<Table,2> state;unsigned calls=0,writes=0,failAt=0,malformAt=0,mutateAt=0;bool after=false;
 std::string malformed;std::vector<std::pair<IptablesTarget,std::string>> commands;
 void seed(const RootImage&v){for(auto&t:state)for(auto&c:v){auto&dst=t.chains[c.name];for(auto&r:c.rules)dst.push_back(ruleText(c,r));}}
 std::string listing(const Table&t){std::string s="-P INPUT "+t.policy[0]+"\n-P OUTPUT "+t.policy[1]+"\n";for(auto&[name,rules]:t.chains)s+="-N "+name+"\n";for(unsigned i=0;i<2;i++)for(auto&r:t.root[i])s+=r+"\n";for(auto&[name,rules]:t.chains)for(auto&r:rules)s+=r+"\n";return s;}
 int execute(IptablesTarget f,const std::string&command,std::string*output)override{
  assert(f==V4||f==V6);assert(!files.empty()&&held);++calls;commands.emplace_back(f,command);
  if(calls==failAt&&!after)return -1;
  auto&t=state[f==V4?0:1];std::istringstream in(command);std::string line;assert(std::getline(in,line)&&line=="*g24sock");std::string text;bool write=false;
  while(std::getline(in,line)){
   if(line=="COMMIT")break;
   if(line=="-S"){assert(output);text+=listing(t);continue;}
   if(line.rfind("-S ",0)==0){assert(output);auto name=line.substr(3);assert(t.chains.count(name));text+="-N "+name+"\n";for(auto&r:t.chains.at(name))text+=r+"\n";continue;}
   assert(!output);write=true;
   if(line.rfind("-N ",0)==0){assert(t.chains.emplace(line.substr(3),std::vector<std::string>{}).second);}
   else if(line.rfind("-A INPUT ",0)==0)t.root[0].push_back(line);
   else if(line.rfind("-A OUTPUT ",0)==0)t.root[1].push_back(line);
   else if(line=="-P INPUT ACCEPT")t.policy[0]="ACCEPT";
   else if(line=="-P OUTPUT ACCEPT")t.policy[1]="ACCEPT";
   else assert(false);
  }
  if(write)++writes;
  if(calls==mutateAt){t.policy[0]="ACCEPT";t.root[0]={"-A INPUT -j g24_owner_in"};}
  if(output)*output=calls==malformAt?malformed:text;
  if(calls==failAt)return -1;
  return 0;
 }
 bool active(){for(auto&t:state)if(t.policy!=std::array<std::string,2>{"ACCEPT","ACCEPT"}||t.root[0]!=std::vector<std::string>{"-A INPUT -j g24_owner_in"}||t.root[1]!=std::vector<std::string>{"-A OUTPUT -j g24_owner_out"})return false;return true;}
};
void initRoots(){resetImage();features=511;}
int main(){
 auto wanted=program();
 initRoots();{NetpolicyLease l;C(l.requireSocketTables()==-ENOTCONN);C(l.start()==0);ioctlEintr=2;C(l.requireSocketTables()==0&&ioctlEintr==0&&held);}
 for(int f:{0,7,127,255}){initRoots();features=f;NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==-EOPNOTSUPP&&files.empty()&&held&&k.calls==0);}
 for(int e:{ENOTTY,EIO,EACCES}){initRoots();NetpolicyLease l;C(l.start()==0);ioctlError=e;errorCommand=GTA3XLWIFI_UID_FEATURES;C(l.requireSocketTables()==-e&&files.empty()&&held);}
 unsigned prepareCalls=0,activateCalls=0;
 initRoots();{NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==0&&held&&!files.empty()&&k.writes==2&&!k.active());prepareCalls=k.calls;C(roots.prepare()==0&&k.writes==2&&held);k.seed(wanted);unsigned before=k.calls;C(roots.activate(wanted)==0&&held&&k.active()&&k.writes==4);activateCalls=k.calls-before;C(roots.verify(wanted)==0&&held);C(roots.activate(wanted)==0&&k.writes==4);C(roots.prepare()==0&&k.writes==4&&k.active());}
 // Every I/O point: failure before or after a possible commit keeps the lease
 // closed/held; an explicit new lease can recover only valid partial state.
 for(bool committed:{false,true})for(unsigned point=1;point<=prepareCalls;point++){
  initRoots();NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0);k.failAt=point;k.after=committed;C(roots.prepare()<0&&held&&files.empty());k.failAt=0;C(l.start()==0&&roots.prepare()==0&&held&&k.writes<=3);
 }
 for(bool committed:{false,true})for(unsigned point=1;point<=activateCalls;point++){
  initRoots();NetpolicyLease l;Tables k;k.seed(wanted);SocketRoots roots(k,l);C(l.start()==0);k.failAt=point;k.after=committed;C(roots.activate(wanted)<0&&held&&files.empty());k.failAt=0;C(l.start()==0&&roots.activate(wanted)==0&&held&&k.active());
 }
 // Both family inventories must pass before the first modification.
 for(unsigned f:{0u,1u})for(int fault=0;fault<12;fault++){
  initRoots();NetpolicyLease l;Tables k;auto&t=k.state[f];
  switch(fault){case 0:t.policy[0]="ACCEPT";break;case 1:t.policy[1]="ACCEPT";break;case 2:t.chains["foreign"]={};break;case 3:t.root[0]={"-A INPUT -j ACCEPT"};break;case 4:t.root[1]={"-A OUTPUT -j g24_owner_in"};break;case 5:t.chains["g24_owner_in"]={};t.root[0]={"-A INPUT -j g24_owner_in","-A INPUT -j g24_owner_in"};break;case 6:t.chains["g24_uid_1"]={"-A g24_uid_1 -j DROP"};break;case 7:t.policy[0]="QUEUE";break;case 8:t.chains["g24_uid_10"]={};break;case 9:t.root[0]={"-A INPUT -j g24_owner_in"};break;case 10:t.chains["g24_uid_1"]={"-A g24_uid_1 -j NFQUEUE"};break;case 11:t.chains["g24_owner_in"]={};t.root[0]={"-A INPUT -j g24_owner_in"};break;}
  SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==-EPROTO&&k.writes==0&&files.empty()&&held);
 }
 for(auto bad:std::vector<std::string>{"", "-P INPUT DROP\n", "-P INPUT DROP\n-P INPUT DROP\n-P OUTPUT DROP\n", "-P INPUT DROP\n-P OUTPUT DROP", "-P INPUT DROP\n-P OUTPUT DROP\n-P FORWARD DROP\n", "-P INPUT DROP\n-P OUTPUT DROP\n\n", std::string("-P INPUT DROP\n-P OUTPUT DROP\n\0",30),"-P INPUT DROP\n-P OUTPUT DROP\n# arbitrary\n",std::string(1024*1024+1,'x')+"\n"}){
  initRoots();NetpolicyLease l;Tables k;k.malformAt=1;k.malformed=bad;SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==-EPROTO&&held&&files.empty()&&k.writes==0);
 }
 // Malformed owned rules and drift are rejected without root activation.
 for(unsigned f:{0u,1u}){
  initRoots();NetpolicyLease l;Tables k;k.seed(wanted);k.state[f].chains["g24_uid_1"].push_back("-A g24_uid_1 -j NFQUEUE");SocketRoots roots(k,l);C(l.start()==0&&roots.activate(wanted)==-EPROTO&&k.writes==0&&held&&files.empty());
  initRoots();NetpolicyLease q;Tables changed;changed.seed(wanted);changed.state[f].chains["g24_uid_1"]={"-A g24_uid_1 -j DROP"};SocketRoots other(changed,q);C(q.start()==0&&other.activate(wanted)==-ESTALE&&held&&files.empty()&&changed.writes==0);
 }
 initRoots();{NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0&&l.release()==0);C(roots.prepare()==-EBUSY&&held&&files.empty()&&k.calls==0);}
 initRoots();{NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0);for(int fault=0;fault<5;fault++){auto bad=wanted;if(fault==0)bad.pop_back();if(fault==1)std::swap(bad[0],bad[1]);if(fault==2)bad.back().rules.clear();if(fault==3)bad[0].rules.push_back({std::nullopt,ChainIO::Verdict::Reject});if(fault==4)bad[9].rules[0].uid=ChainIO::UidRange{0,10000};C(roots.activate(bad)==-EINVAL&&k.calls==0&&!files.empty()&&held);C(roots.verify(bad)==-EINVAL&&k.calls==0&&!files.empty());}}
 // Fresh chain creation must not silently enable a root during readback.
 initRoots();{NetpolicyLease l;Tables k;k.mutateAt=4;SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==-EPROTO&&held&&files.empty());}
 // A valid half-activated family is recoverable under a new held lease.
 initRoots();{NetpolicyLease l;Tables k;k.seed(wanted);k.state[0].root[0]={"-A INPUT -j g24_owner_in"};k.state[0].policy[0]="ACCEPT";SocketRoots roots(k,l);C(l.start()==0&&roots.activate(wanted)==0&&held&&k.active());}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code)
names=['Gta3xlwifiNetpolicyLease','Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiSocketRoots'];sources=[S/(n+'.cpp') for n in names]
cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',r.stdout);assert m and int(m[1])>=180
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,checked,*sources,*[p.with_suffix('.h') for p in sources],O/'test.cpp',*[p for p in (S/'linux/netfilter').glob('*.h')]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':r.stderr,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'all_success_io_points_fault_tested':True,'never_releases_gate':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; actual dual-stack private root/bootstrap C++, fatal UBSan fixtures')
