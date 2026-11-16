#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay actual Controllers root choices and startup caller against real guard code.

Properties, lease, rule execution and other startup components are host fixtures.
This proves the missing OUTPUT guard/default-mode bug and strict guarded startup
ordering; it does not prove Android networking, kernel packet behavior or Ready.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['composition','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();C=a.composition;O=a.output;assert not O.exists();O.mkdir(parents=True)
def extract(s,m):
 start=s.index(m);b=s.index('{',start);i=b+1;depth=1
 while depth:
  depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[start:i]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();rel='system/netd/server/Controllers.cpp';baseline=(C/'baseline'/rel).read_text();builder=extract(baseline,'int Controllers::createChildChains(');init=extract(baseline,'int Controllers::initChildChains()');calls=re.findall(r'createChildChains\((V4V6|V4|V6), "filter", "(INPUT|FORWARD|OUTPUT)", \w+, (true|false)\)',init);assert len(calls)==4
projection=(C/'Gta3xlwifiSocketPolicyProjection.cpp').read_text();startup=extract(projection,'int SocketPolicyProjection::startWithAccounting(');guards=(C/'projection-guards.inc').read_text()
fixture=r'''
#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>
enum IptablesTarget { V4,V6,V4V6 };
static unsigned ioCount,ioFault;static bool ioAfter,held=true;
static bool point(){return ++ioCount==ioFault;}
namespace android::base {static bool GetBoolProperty(const char*,bool){return true;}}
static std::string StringPrintf(const char*f,...){char b[4096];va_list a;va_start(a,f);int n=vsnprintf(b,sizeof(b),f,a);va_end(a);assert(n>=0&&n<int(sizeof(b)));return b;}
static void StringAppendF(std::string*s,const char*f,...){char b[4096];va_list a;va_start(a,f);int n=vsnprintf(b,sizeof(b),f,a);va_end(a);assert(n>=0&&n<int(sizeof(b)));*s+=b;}
struct Kernel {
 std::array<std::array<std::vector<std::string>,3>,2> rows;unsigned writes=0;
 static unsigned id(const std::string&s){return s=="INPUT"?0:s=="FORWARD"?1:s=="OUTPUT"?2:3;}
 int execute(IptablesTarget family,const std::string&command,std::string*out){
  if(family==V4V6){int a=execute(V4,command,out);int b=execute(V6,command,out);return a|b;}
  bool fail=point();if(fail&&!ioAfter)return -1;
  std::istringstream in(command);std::string line;assert(std::getline(in,line)&&line=="*filter");
  while(std::getline(in,line)){
   if(line=="COMMIT")continue;
   if(line.rfind("-S ",0)==0){assert(out);unsigned n=id(line.substr(3));assert(n<3);*out="-P "+line.substr(3)+" ACCEPT\n";for(const auto&r:rows[family][n])*out+=r+"\n";continue;}
   if(line.front()==':')continue;
   std::istringstream w(line);std::string op,name;w>>op>>name;unsigned n=id(name);if(n==3)continue;
   if(op=="-F")rows[family][n].clear();
   else if(op=="-A")rows[family][n].push_back(line);
   else if(op=="-I"){std::string position;w>>position;assert(position=="1");rows[family][n].insert(rows[family][n].begin(),"-A "+name+line.substr(line.find(" 1 ")+2));++writes;}
   else assert(false);
  }
  return fail?-1:0;
 }
};
static Kernel* kernel;
static const char* CHILD_CHAIN_TEMPLATE="-A %s -j %s\n";
struct Controllers {
 static int createChildChains(IptablesTarget,const char*,const char*,const std::vector<const char*>&,bool);
 static std::set<std::string> findExistingChildChains(IptablesTarget,const char*,const char*){return {};}
 static int execIptablesRestore(IptablesTarget f,const std::string&s){return kernel->execute(f,s,nullptr);}
};
namespace android::net::gta3xlwifi {
struct AccountingRoots {using Program=std::vector<std::string>;static bool validProgram(const Program&p){return p==Program{"fixture"};}int prepare(const Program&){return point()?-EIO:0;}int verifyProducers(){return point()?-EIO:0;}};
struct Component {int prepare(){return point()?-EIO:0;}};
struct Lease {int isHeld(bool*v){*v=held;return point()?-EIO:0;}};
class SocketPolicyProjection {public:
 enum class HookMode {VerifyOnly,InstallMissing};
 explicit SocketPolicyProjection(Kernel&k):mKernel(k){}
 int startWithAccounting(const AccountingRoots::Program&,HookMode=HookMode::VerifyOnly);
 int prepareHooks(HookMode);int verifyHooks();
 int acquireAccountingLeaseLocked(){return 0;}int quarantine(int r){held=true;return r;}
 std::mutex mMutex;bool mStarted=false,mControllerLeasePrepared=true,mAccountingEnabled=false;
 Kernel&mKernel;Lease mLease;AccountingRoots mAccounting;Component mSocket,mMeter;
};
'''
footer=r'''
static void initial(Kernel&k){kernel=&k;std::vector<const char*> child={"fixture_child"};
INITIAL_CALLS
 ioCount=ioFault=0;held=true;}
int main(){unsigned points=0;
 {Kernel k;initial(k);for(const auto&f:k.rows){assert(f[0][0].find("gta3xlwifi_guard")!=std::string::npos);assert(f[1][0].find("gta3xlwifi_guard")!=std::string::npos);assert(f[2][0].find("gta3xlwifi_guard")==std::string::npos);}
 P p(k);P* gta3xlwifiPolicyOwner=&p;AccountingRoots::Program program={"fixture"};int r=CALL;
 if(BASELINE){assert(r==-EPROTO&&held&&!p.mStarted&&k.writes==0);puts("original_missing_OUTPUT_guard_EPROTO");return 0;}
 assert(r==0&&held&&p.mStarted&&p.mAccountingEnabled&&k.writes==2);points=ioCount;
 for(unsigned f=0;f<2;f++)for(unsigned n=0;n<3;n++){const char*names[]={"INPUT","FORWARD","OUTPUT"};assert(k.rows[f][n].size()==2);assert(k.rows[f][n][0]==std::string("-A ")+names[n]+" -m gta3xlwifi_guard -j DROP");assert(k.rows[f][n][1]==std::string("-A ")+names[n]+" -j fixture_child");}}
 for(bool after:{false,true})for(unsigned pointId=1;pointId<=points;pointId++){Kernel k;initial(k);P p(k);P*gta3xlwifiPolicyOwner=&p;AccountingRoots::Program program={"fixture"};ioFault=pointId;ioAfter=after;int r=CALL;assert(r<0&&held&&!p.mStarted);ioFault=0;}
 {Kernel k;initial(k);P first(k);P*gta3xlwifiPolicyOwner=&first;AccountingRoots::Program program={"fixture"};assert(CALL==0);auto rows=k.rows;unsigned writes=k.writes;P second(k);gta3xlwifiPolicyOwner=&second;assert(CALL==0&&held&&k.rows==rows&&k.writes==writes);}
 printf("fixed_all_six_roots_held start_fault_points=%u\n",points);
}
'''
footer=footer.replace('INITIAL_CALLS','\n'.join(f'assert(Controllers::createChildChains({f},"filter","{n}",child,{e})==0);' for f,n,e in calls))
results=[]
for kind in ['baseline','files']:
 s=(C/kind/rel).read_text();assert extract(s,'int Controllers::createChildChains(')==builder and extract(s,'int Controllers::initChildChains()')==init
 call=re.search(r'gta3xlwifiPolicyOwner->startWithAccounting\((.*?)\)',s,re.S).group();call=call.replace('gta3xlwifi::SocketPolicyProjection','P');cpp=O/(kind+'.cpp');code=fixture+guards+'\n'+startup+'\n}\n'+builder+'\nusing namespace android::net::gta3xlwifi;using P=SocketPolicyProjection;\n'+footer.replace('CALL',call).replace('BASELINE','true' if kind=='baseline' else 'false');cpp.write_text(code)
 exe=O/kind;cmd=['g++','-std=c++20','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(cpp),'-o',str(exe)];x=subprocess.run(cmd,capture_output=True,text=True);assert x.returncode==0,x.stderr;x=subprocess.run([str(exe)],capture_output=True,text=True);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);results.append({'kind':kind,'actual_call':call,'stdout':x.stdout,'stderr':x.stderr})
r={'passed':True,'scope':__doc__,'missing_output_guard_reproduced':True,'fixed_installs_and_verifies_all_six_guard_roots':True,'failure_injection_keeps_held_and_unstarted':True,'foreign_root_rules_preserved_and_existing_guards_not_duplicated':True,'source_sha256':{rel:sha(C/'files'/rel)},'unchanged_projection_source_sha256':sha(C/'Gta3xlwifiSocketPolicyProjection.cpp'),'unchanged_guard_implementation_sha256':sha(C/'projection-guards.inc'),'cases':results,'policy_kernel_crypto_and_boot_failure_guards_changed':False,'hardware_networking_or_Ready_proven':False,'flash_ready':False};(O/'report.json').write_text(json.dumps(r,indent=2)+'\n');print('PASS actual first-boot OUTPUT guard regression, all six root verification and held failure injection')
