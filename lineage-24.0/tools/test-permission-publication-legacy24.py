#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test ordinary dispatch and combined UID publication using real dual-family/lease C++ code.

Sysfs/device/ioctls and ordered iptables tables are fixtures, not actual kernel
execution. Actual policy/compiler/encoder/dual-family/lifecycle code is exercised.
This is UID transaction evidence, not complete packet dispatch or readiness.
"""
import argparse,ast,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-netpolicy-lease24.py');tree=ast.parse(helper.read_text());code=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='code' for t in n.targets));code=code[:code.index('int main(){')]
(O/'IptablesRestoreController.h').write_text('''#pragma once
#include <string>
#ifndef EREMOTEIO
#define EREMOTEIO 121
#endif
#ifndef EUCLEAN
#define EUCLEAN 117
#endif
enum IptablesTarget{V4=1,V6=2,V4V6=3};
class IptablesRestoreInterface{public:virtual ~IptablesRestoreInterface()=default;virtual int execute(IptablesTarget,const std::string&,std::string*)=0;};
''');assert not (S/'IptablesRestoreController.h').exists()
code+=r'''
#include "Gta3xlwifiUidPolicyTransaction.h"
#include <atomic>
#include <climits>
#include <condition_variable>
#include <sstream>
using namespace android::net::gta3xlwifi;
using P=UidPolicyTransaction;using Image=UidChainProgram::Image;
struct Kernel:IptablesRestoreInterface{
 std::map<IptablesTarget,std::map<std::string,std::string>> tables;
 unsigned calls=0,writes=0,reads=0,failWriteAt=0,failAfter=0,badReadAt=0;
 bool commitFailure=true,badHook=false,pause=false,blocked=false,resume=false;
 std::mutex gate;std::condition_variable cv;
 Kernel(){for(auto f:{V4,V6}){for(int i=1;i<=9;i++)tables[f]["g24_uid_"+std::to_string(i)]="";
  for(auto name:{"g24_meter_deny","g24_meter_allow","g24_data_saver","g24_owner_in","g24_owner_out"})tables[f][name]="";}}
 int execute(IptablesTarget f,const std::string& command,std::string* output)override{
  assert((f==V4||f==V6)&&held&&opens==1);++calls;
  for(auto chain:{"INPUT","FORWARD","OUTPUT"})if(command=="*filter\n-S "+std::string(chain)+"\nCOMMIT\n"){
   assert(output);*output="-P "+std::string(chain)+" ACCEPT\n";
   if(!badHook)*output+="-A "+std::string(chain)+" -m gta3xlwifi_guard -j DROP\n";
   *output+="-A "+std::string(chain)+" -j fw_test\n";return 0;
  }
  std::istringstream stream(command);std::string line;assert(std::getline(stream,line)&&line=="*filter");
  auto next=tables[f];std::string result;bool write=false;
  while(std::getline(stream,line)){
   if(line=="COMMIT")break;
   if(line.rfind("-S g24_",0)==0){assert(output&&!write);auto name=line.substr(3);result+="-N "+name+"\n"+tables[f][name];continue;}
   assert(!output);write=true;
   if(line.rfind(":g24_",0)==0){auto end=line.find(' ');assert(line.substr(end)==" -");next[line.substr(1,end-1)]="";continue;}
   assert(line.rfind("-A g24_",0)==0);auto end=line.find(' ',3);auto name=line.substr(3,end-3);assert(next.count(name));
   if(line.size()>=10&&line.substr(line.size()-10)==" -j REJECT")line+=" --reject-with "+std::string(f==V4?"icmp-port-unreachable":"icmp6-port-unreachable");
   next[name]+=line+"\n";
  }
  assert(line=="COMMIT"&&!std::getline(stream,line));
  if(output){++reads;*output=reads==badReadAt?"bad":result;return 0;}
  assert(write);++writes;
  if(pause&&f==V6){std::unique_lock<std::mutex> lock(gate);blocked=true;cv.notify_all();cv.wait(lock,[&]{return resume;});pause=false;}
  bool fail=writes==failWriteAt||(failAfter&&writes>=failAfter);
  if(!fail||commitFailure)tables[f]=std::move(next);
  return fail?-1:0;
 }
};
UidPolicy configured(){UidPolicy p;assert(p.setChainEnabled(1,true)==0);assert(p.replaceUidChain(1,{10001})==0);p.setDataSaver(true);assert(p.replaceUidChain(10,{10001})==0);return p;}
int main(){
 Image image{{"sentinel",{}}},sentinel=image;UidPolicy empty;
 C(P::compile(empty,nullptr)==-EINVAL);C(P::compile(empty,&image)==0&&image.size()==14);
 UidPolicy aggregate;std::vector<int32_t> many;for(int i=0;i<10000;i++)many.push_back(10000+2*i);
 assert(aggregate.setChainEnabled(1,true)==0&&aggregate.replaceUidChain(1,many)==0&&aggregate.replaceUidChain(11,many)==0);
 C(UidChainProgram::ordinary(aggregate,&image)==0);C(MeteredChainProgram::compile(aggregate,&image)==0);image=sentinel;
 C(P::compile(aggregate,&image)==-E2BIG&&image==sentinel);
 reset();{
  Kernel k;P p(k);bool enabled=true;int32_t rule=777;uint32_t reason=777;
  C(p.getChainEnabled(1,&enabled)==-EAGAIN&&enabled);C(p.getUidRule(1,10001,&rule)==-EAGAIN&&rule==777);C(p.blockedReasons(10001,&reason)==-EAGAIN&&reason==777);C(p.isNetworkingBlocked(10001,true)==-EAGAIN);
  C(p.replace(empty)==-ENOTCONN&&k.calls==0);C(p.setDataSaver(true)==-EAGAIN);
  C(p.start()==0&&held);C(p.start()==-EALREADY&&held);C(p.setUidRule(1,10001,UidPolicy::Allow)==-EAGAIN&&k.writes==0);
  C(p.replace(configured())==0&&!held&&k.writes==2&&k.tables[V4].size()==14&&k.tables[V6].size()==14);
  C(p.getChainEnabled(1,&enabled)==0&&enabled);C(p.getUidRule(1,10001,&rule)==0&&rule==UidPolicy::Allow);C(p.isNetworkingBlocked(10001,true)==0);C(p.isNetworkingBlocked(10002,true)==1);
  C(p.setUidRule(1,10002,UidPolicy::Allow)==0);C(p.setUidRule(10,10002,UidPolicy::Allow)==0&&p.isNetworkingBlocked(10002,true)==0);
  C(p.setUidRule(11,10002,UidPolicy::Deny)==0&&p.isNetworkingBlocked(10002,true)==1&&p.isNetworkingBlocked(10002,false)==0);
  C(p.removeUid(10002)==0&&p.isNetworkingBlocked(10002,false)==1);
  C(p.setChainEnabled(1,false)==0&&p.isNetworkingBlocked(10002,false)==0);C(p.setDataSaver(false)==0&&p.isNetworkingBlocked(10002,true)==0);
  C(p.replaceUidChain(12,{10003,10004})==0&&p.getUidRule(12,10003,&rule)==0&&rule==UidPolicy::Deny);
  auto calls=k.calls;C(p.setUidRule(13,10001,UidPolicy::Allow)==-EINVAL);C(p.setUidRule(1,-1,UidPolicy::Allow)==-EINVAL);C(p.setUidRule(1,10001,99)==-EINVAL);C(p.replaceUidChain(1,{10001,-1})==-EINVAL);C(p.removeUid(-1)==-EINVAL);C(p.setChainEnabled(0,true)==-EINVAL);C(k.calls==calls);
  C(p.replace(aggregate)==-E2BIG&&k.calls==calls&&p.isNetworkingBlocked(10002,true)==0);
  enabled=true;C(p.getChainEnabled(0,&enabled)==-EINVAL&&enabled);rule=777;C(p.getUidRule(1,-1,&rule)==-EINVAL&&rule==777);reason=777;C(p.blockedReasons(-1,&reason)==-EINVAL&&reason==777);
  C(p.start()==-EALREADY&&p.isNetworkingBlocked(10002,true)==0);
  p.stop();C(held&&files.empty()&&p.isNetworkingBlocked(10001,true)==-EAGAIN);p.stop();C(closes==1);C(p.start()==0&&held&&p.isNetworkingBlocked(10001,true)==-EAGAIN);C(p.replace(configured())==0&&!held);
 }
 C(held&&files.empty());
 // Both families, acknowledgements after possible commit, first/later updates.
 for(bool prior:{false,true})for(unsigned failure:{1u,2u})for(bool committed:{false,true}){
  reset();Kernel k;P p(k);C(p.start()==0);if(prior)C(p.replace(empty)==0);
  auto old=k.tables;k.writes=0;k.failWriteAt=failure;k.commitFailure=committed;
  C(p.replace(configured())==-EREMOTEIO&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);C(k.tables==old);
  C(p.replace(empty)==-ENOTCONN);k.failWriteAt=0;C(p.start()==0&&held);C(p.replace(configured())==0&&!held&&p.isNetworkingBlocked(10001,true)==0);
 }
 reset();{Kernel k;P p(k);C(p.start()==0&&p.replace(empty)==0);k.writes=0;k.failAfter=2;C(p.replace(configured())==-EUCLEAN&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);}
 reset();{Kernel k;P p(k);C(p.start()==0&&p.replace(empty)==0);k.badHook=true;C(p.replace(configured())==-EPROTO&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);}
 reset();{Kernel k;P p(k);C(p.start()==0&&p.replace(empty)==0);k.badReadAt=k.reads+1;C(p.replace(configured())==-EPROTO&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);}
 reset();{Kernel k;P p(k);C(p.start()==0);ioctlError=EIO;errorCommand=GTA3XLWIFI_NETPOLICY_RELEASE;commitError=true;C(p.replace(configured())==-EUCLEAN&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);}
 reset();abi=2;{Kernel k;P p(k);C(p.start()==-EPROTO&&held&&files.empty());C(p.replace(empty)==-ENOTCONN);}
 // A syntactically similar foreign target must not be normalized to an
 // owned chain during readback or restored as an owned dependency.
 for(const std::string target:{"g24_uid_01","g24_uid_0","g24_uid_10","foreign"}){
  reset();Kernel k;P p(k);C(p.start()==0&&p.replace(empty)==0);
  k.tables[V4]["g24_owner_in"]="-A g24_owner_in -j "+target+"\n";
  auto writes=k.writes;C(p.setDataSaver(true)==-EPROTO&&held&&files.empty()&&k.writes==writes);
  C(p.isNetworkingBlocked(10001,true)==-EAGAIN);
 }
 // Real owner mutex serializes concurrent read/modify/commit operations.
 reset();{Kernel k;P p(k);C(p.start()==0&&p.replace(configured())==0);std::vector<std::thread> threads;
  for(int i=0;i<24;i++)threads.emplace_back([&,i]{assert(p.setUidRule(1,20000+i,UidPolicy::Allow)==0);});
  for(auto& t:threads){t.join();}
  for(int i=0;i<24;i++){int32_t rule=0;C(p.getUidRule(1,20000+i,&rule)==0&&rule==UidPolicy::Allow);}C(k.tables[V4].size()==14&&k.tables[V6].size()==14);
 }
 // A reader admitted during a paused second-family commit sees only committed
 // state after its owner lock is released, never the staged candidate.
 for(bool fail:{false,true}){
  reset();Kernel k;P p(k);C(p.start()==0&&p.replace(empty)==0);k.pause=true;if(fail)k.failWriteAt=k.writes+2;
  int writeResult=777,readResult=777;std::atomic<bool> readerStarted{false};
  std::thread writer([&]{writeResult=p.setDataSaver(true);});
  {std::unique_lock<std::mutex> lock(k.gate);k.cv.wait(lock,[&]{return k.blocked;});}
  std::thread reader([&]{readerStarted=true;readResult=p.isNetworkingBlocked(10001,true);});
  while(!readerStarted.load())std::this_thread::yield();
  {std::lock_guard<std::mutex> lock(k.gate);k.resume=true;}k.cv.notify_all();writer.join();reader.join();
  C(writeResult==(fail?-EREMOTEIO:0));C(readResult==(fail?-EAGAIN:1));C(fail?held:!held);
 }
 C(held&&files.empty());printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code)
names=['Gta3xlwifiCheckedUidChains','Gta3xlwifiNetpolicyLease','Gta3xlwifiDualStackUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiMeteredChainProgram','Gta3xlwifiUidPolicyTransaction','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiUidPermissionState'];sources=[S/(n+'.cpp') for n in names]
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=90);(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',r.stdout);assert m and int(m[1])>=100
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[x.with_suffix('.h') for x in sources],S/'linux/netfilter/gta3xlwifi_netpolicy.h']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':r.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; real eight-source ordinary dispatch/UID transaction/lease/publication, fatal UBSan fixtures')
