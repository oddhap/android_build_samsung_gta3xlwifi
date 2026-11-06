#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test real dual-stack chain transactions and lease transport with I/O fixtures.

Actual C++ parsers/transport/transactions run with fatal UBSan. Sysfs, device,
ioctls and ordered rule tables are fixtures, not kernel packets or readiness.
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
code+='''
#include "Gta3xlwifiDualStackUidChains.h"
using D=android::net::gta3xlwifi::DualStackUidChains;
using Chains=android::net::gta3xlwifi::CheckedUidChains;
D::Image image(unsigned uid){return {{"g24_uid",{{Chains::UidRange{uid,uid},Chains::Verdict::Return},{std::nullopt,Chains::Verdict::Drop}}}};}
struct Kernel:IptablesRestoreInterface{
 std::map<IptablesTarget,unsigned> uid{{V4,10001},{V6,10001}};
 std::map<std::pair<IptablesTarget,std::string>,bool> guards;
 Kernel(){for(auto f:{V4,V6})for(auto c:{"INPUT","FORWARD","OUTPUT"})guards[{f,c}]=true;}
 void missing(){for(auto& pair:guards)pair.second=false;}
 unsigned calls=0,writes=0,uidReads=0,failWriteAt=0,failAfter=0,badUidReadAt=0;
 int badFamily=0;std::string badChain,overrideText;bool changeHooksOnWrite=false,commitFailure=true;
 int execute(IptablesTarget f,const std::string& command,std::string* output)override{
  assert(f==V4||f==V6);assert(held&&opens==1);++calls;
  for(auto chain:{"INPUT","FORWARD","OUTPUT"}){
   if(command=="*filter\\n-S "+std::string(chain)+"\\nCOMMIT\\n"){
    assert(output);*output="-P "+std::string(chain)+" ACCEPT\\n";if(guards[{f,chain}])*output+="-A "+std::string(chain)+" -m gta3xlwifi_guard -j DROP\\n";*output+="-A "+std::string(chain)+" -j fw_test\\n";
    if(int(f)==badFamily&&chain==badChain)*output=overrideText;
    return 0;
   }
  }
  if(command=="*filter\\n-S g24_uid\\nCOMMIT\\n"){
   assert(output);++uidReads;
   *output="-N g24_uid\\n-A g24_uid -m owner --uid-owner "+std::to_string(uid[f])+" -j RETURN\\n-A g24_uid -j DROP\\n";
   if(uidReads==badUidReadAt)*output="bad";
   return 0;
  }
  if(command.rfind("*filter\\n-I ",0)==0){
   assert(output==nullptr);++writes;bool fail=writes==failWriteAt||(failAfter&&writes>=failAfter);
   std::string expected="*filter\\n";
   for(auto c:{"INPUT","FORWARD","OUTPUT"})if(!guards[{f,c}])expected+="-I "+std::string(c)+" 1 -m gta3xlwifi_guard -j DROP\\n";
   expected+="COMMIT\\n";assert(command==expected);
   if(!fail||commitFailure)for(auto c:{"INPUT","FORWARD","OUTPUT"})guards[{f,c}]=true;
   return fail?-1:0;
  }
  assert(output==nullptr);assert(command.rfind("*filter\\n:g24_uid -\\n-A g24_uid -m owner --uid-owner ",0)==0);
  auto pos=command.find("--uid-owner ")+12;unsigned value=std::stoul(command.substr(pos));++writes;
  bool fail=writes==failWriteAt||(failAfter&&writes>=failAfter);
  if(!fail||commitFailure)uid[f]=value;
  if(changeHooksOnWrite){badFamily=V6;badChain="OUTPUT";overrideText="-P OUTPUT ACCEPT\\n-A OUTPUT -j ACCEPT\\n";}
  return fail?-1:0;
 }
};
int main(){
 reset();{Kernel k;D d(k);C(d.replace(image(110001),image(110001))==-ENOTCONN&&k.calls==0);C(d.start()==0&&held);C(d.start()==-EALREADY&&k.calls==6);C(d.replace(image(110001),image(110001))==0&&!held&&k.uid[V4]==110001&&k.uid[V6]==110001);C(d.replace(image(110001),image(110001))==0&&!held&&k.writes==2);d.stop();C(held&&opens==0);d.stop();C(closes==1);}
 for(int f:{int(V4),int(V6)})for(auto chain:{"INPUT","FORWARD","OUTPUT"}){
  reset();Kernel k;k.badFamily=f;k.badChain=chain;k.overrideText="-P "+std::string(chain)+" ACCEPT\\n";D d(k);C(d.start()==-EPROTO&&held&&files.empty()&&k.writes==0);C(d.replace(image(110001),image(110001))==-ENOTCONN);
 }
 for(auto bad:std::vector<std::string>{"","-P INPUT ACCEPT\\n-A INPUT -j ACCEPT\\n-A INPUT -m gta3xlwifi_guard -j DROP\\n","-P INPUT ACCEPT\\n-A INPUT -m gta3xlwifi_guard -j RETURN\\n","-P INPUT ACCEPT\\n-A INPUT -o lo -m gta3xlwifi_guard -j DROP\\n","-P INPUT ACCEPT\\n-A INPUT -m gta3xlwifi_guard -j DROP","-P INPUT ACCEPT\\r\\n-A INPUT -m gta3xlwifi_guard -j DROP\\n","-P INPUT ACCEPT\\n-A INPUT -m gta3xlwifi_guard -j DROP\\n-N foreign\\n",std::string(1024*1024+1,'x')}){
  reset();Kernel k;k.badFamily=V4;k.badChain="INPUT";k.overrideText=bad;D d(k);C(d.start()==-EPROTO&&held&&files.empty());
 }
 reset();{Kernel k;k.badFamily=V4;k.badChain="INPUT";k.overrideText="-P INPUT DROP\\n-A INPUT -m gta3xlwifi_guard -j DROP\\n";D d(k);C(d.start()==0&&held);}
 reset();abi=2;{Kernel k;D d(k);C(d.start()==-EPROTO&&k.calls==0&&held&&files.empty());}
 for(auto failure:{1u,2u})for(bool committed:{false,true}){
  reset();Kernel k;D d(k);C(d.start()==0);k.failWriteAt=failure;k.commitFailure=committed;C(d.replace(image(110001),image(110001))==-EREMOTEIO&&held&&k.uid[V4]==10001&&k.uid[V6]==10001);k.failWriteAt=0;C(d.replace(image(120001),image(120001))==0&&!held&&k.uid[V4]==120001&&k.uid[V6]==120001);
 }
 reset();{Kernel k;D d(k);C(d.start()==0&&d.replace(image(110001),image(110001))==0);k.writes=0;k.failWriteAt=2;C(d.replace(image(120001),image(120001))==-EREMOTEIO&&!held&&k.uid[V4]==110001&&k.uid[V6]==110001);}
 reset();{Kernel k;D d(k);C(d.start()==0);k.failAfter=2;C(d.replace(image(110001),image(110001))==-EUCLEAN&&held&&files.empty());auto calls=k.calls;C(d.replace(image(120001),image(120001))==-ENOTCONN&&k.calls==calls);}
 reset();{Kernel k;D d(k);C(d.start()==0);k.badUidReadAt=1;C(d.replace(image(110001),image(110001))==-EPROTO&&held&&files.empty()&&k.writes==0);}
 reset();{Kernel k;D d(k);C(d.start()==0);k.badUidReadAt=7;C(d.replace(image(110001),image(110001))==-EPROTO&&held&&k.uid[V4]==10001&&k.uid[V6]==10001);}
 reset();{Kernel k;D d(k);C(d.start()==0);k.changeHooksOnWrite=true;C(d.replace(image(110001),image(110001))==-EUCLEAN&&held&&files.empty());}
 reset();{Kernel k;D d(k);C(d.start()==0);ioctlError=EIO;errorCommand=GTA3XLWIFI_NETPOLICY_RELEASE;commitError=true;C(d.replace(image(110001),image(110001))==-EUCLEAN&&held&&files.empty());auto calls=k.calls;C(d.replace(image(120001),image(120001))==-ENOTCONN&&k.calls==calls);}
 reset();{Kernel k;D d(k);C(d.start()==0);ioctlError=EPERM;errorCommand=GTA3XLWIFI_NETPOLICY_HOLD;C(d.replace(image(110001),image(110001))==-EPERM&&held&&files.empty()&&k.writes==0);}
 reset();{Kernel k;D d(k);C(d.start()==0);auto invalid=image(110001);invalid[0].name="foreign";C(d.replace(invalid,image(110001))==-EINVAL&&held&&files.empty()&&k.writes==0);}
 reset();{Kernel k;D d(k);C(d.start()==0);auto invalid=image(110001);invalid[0].rules[0].uid=Chains::UidRange{20,10};C(d.replace(image(110001),invalid)==-EINVAL&&held&&k.uid[V4]==10001&&k.uid[V6]==10001);}
 using Mode=D::HookMode;
 reset();{Kernel k;k.missing();D d(k);C(d.start(Mode::InstallMissing)==0&&held&&k.writes==2);for(auto f:{V4,V6})for(auto c:{"INPUT","FORWARD","OUTPUT"})C((k.guards[{f,c}]));C(d.replace(image(110001),image(110001))==0&&!held);}
 reset();{Kernel k;D d(k);C(d.start(Mode::InstallMissing)==0&&held&&k.writes==0);}
 reset();{Kernel k;k.guards[{V6,"OUTPUT"}]=false;D d(k);C(d.start(Mode::InstallMissing)==0&&held&&k.writes==1);}
 for(auto failure:{1u,2u})for(bool committed:{false,true}){
  reset();Kernel k;k.missing();k.failWriteAt=failure;k.commitFailure=committed;D d(k);C(d.start(Mode::InstallMissing)==-EREMOTEIO&&held&&files.empty());C(d.replace(image(110001),image(110001))==-ENOTCONN);k.failWriteAt=0;C(d.start(Mode::InstallMissing)==0&&held);C(d.replace(image(120001),image(120001))==0&&!held);
 }
 reset();{Kernel k;k.missing();k.badFamily=V6;k.badChain="OUTPUT";k.overrideText="-P OUTPUT ACCEPT\\n-A OUTPUT -j ACCEPT\\n-A OUTPUT -m gta3xlwifi_guard -j DROP\\n";D d(k);C(d.start(Mode::InstallMissing)==-EPROTO&&held&&files.empty()&&k.writes==0);}
 reset();{Kernel k;D d(k);C(d.start(static_cast<Mode>(9))==-EINVAL&&held&&files.empty()&&k.calls==0);}
 C(files.empty()&&held);printf("passed_cases=%u\\n",cases);
}
'''
(O/'test.cpp').write_text(code)
sources=[S/n for n in ['Gta3xlwifiCheckedUidChains.cpp','Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiDualStackUidChains.cpp']]
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=30);(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',r.stdout);assert m and int(m[1])>=60
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[S/n for n in ['Gta3xlwifiCheckedUidChains.h','Gta3xlwifiNetpolicyLease.h','Gta3xlwifiDualStackUidChains.h','linux/netfilter/gta3xlwifi_netpolicy.h']]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':r.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; real both-family transaction/lease/hook verifier, fatal UBSan fixtures')
