#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute actual Controllers init and private bandwidth reset with boundary fixtures.

Dependencies/exit/lease are fixtures. Preserves stock source bodies and class
layouts. Does not execute Android services or packets.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','runtime-source','guard-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve()/'system/netd/server';B=a.runtime_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');sp=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
controllers=(S/'Controllers.cpp').read_text();bw=(S/'BandwidthController.cpp').read_text();reset=m.extract(bw,'BandwidthController::prepareGta3xlwifiBandwidthControl');init=m.extract(controllers,'Controllers::init');get=m.extract(controllers,'Controllers::gta3xlwifiPolicy')
assert bw== (B/'BandwidthController.cpp').read_text()+'\n// Called only by Controllers after acquiring the private held owner lease.\n// Preserve old per-interface user chains as the stock flush command does; none\n// is replayed or reattached. AccountingRoots validates all owned parents in both\n// families before installing source-bound producers and metered bridges.\n'+reset+'\n'
addition='''    friend class android::net::Controllers;
    // Reset only stock bandwidth-owned parents under the prepared owner lease.
    // The owner installs and verifies real producers afterwards.
    int prepareGta3xlwifiBandwidthControl();
'''
assert (S/'BandwidthController.h').read_text().replace('namespace android::net { class Controllers; }\n\n','',1).replace(addition,'',1)==(B/'BandwidthController.h').read_text()
assert (S/'Controllers.h').read_text().replace('namespace gta3xlwifi { class SocketPolicyProjection; }\n\n','',1).replace('    // Sole process owner, null on the stock path; non-null is NOT readiness.\n    gta3xlwifi::SocketPolicyProjection* gta3xlwifiPolicy() const;','',1).replace('    void init();\n\n','    void init();\n',1)==(A/'Controllers.h').read_text()
# No Controllers changes outside the reviewed guard prerequisite and init/getter.
g=(a.guard_source/'Controllers.cpp').read_text();recovered=controllers.replace('#include "Gta3xlwifiSocketPolicyProjection.h"\n','',1)
recovered=recovered.replace('// Created on main-thread startup before Binder publication. The pointer is then\n// immutable for the process lifetime; no second lease or global Ready flag.\nstd::unique_ptr<gta3xlwifi::SocketPolicyProjection> gta3xlwifiPolicyOwner;\n','',1).replace(get+'\n\n','',1).replace(init,m.extract(g,'Controllers::init'),1);assert recovered==g
start=bw.index('static const std::vector<std::string> IPT_FLUSH_COMMANDS = {');end=bw.index('\n};',start)+3;flush=bw[start:end]
code=r'''
#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>
struct Exit{int code;};
struct Fixture{bool legacy=false,held=false;int lease=0,roots=0,flush=0,owner=0,route=0,xfrm=0;std::vector<std::string> events;std::string flushText;} f;
[[noreturn]] void testExit(int code){throw Exit{code};}
#define exit testExit
std::string Join(const std::vector<std::string>& v,char c){std::string s;for(auto&x:v){if(!s.empty())s+=c;s+=x;}return s;}
enum IptablesTarget{V4,V6,V4V6};
const std::string COMMIT_AND_CLOSE="COMMIT\n";
struct BandwidthController{
 std::map<std::string,int> mSharedQuotaIfaces{{"old",1}},mQuotaIfaces{{"old",1}};
 int64_t mGlobalAlertBytes=5,mSharedQuotaBytes=7;
 int prepareGta3xlwifiBandwidthControl();
 static std::vector<std::string> makeGta3xlwifiAccountingCommands(){f.events.push_back("factory");return {"REAL_FACTORY"};}
 int enableBandwidthControl(){assert(!f.legacy);f.events.push_back("stock");return f.flush;}
 static int iptablesRestoreFunction(IptablesTarget t,const std::string& text,std::string* out){assert(t==V4V6&&!out&&f.held);f.events.push_back("flush");f.flushText=text;return f.flush;}
};
'''+flush+'\n'+reset+r'''
namespace android::base{bool GetBoolProperty(const char*name,bool fallback){assert(!strcmp(name,"ro.gta3xlwifi.legacy_networking")&&!fallback);return f.legacy;}}
namespace android::net{
struct Log{template<class...T>void error(const char*,T...){ }template<class...T>void info(const char*,T...){ }} gLog;
struct Stopwatch{long getTimeAndResetUs(){return 0;}};
struct Status{int value;};bool isOk(Status s){return s.value==0;}
namespace netdutils{std::string toString(Status){return "failure";}}
struct RouteController{static int Init(int id){assert(id==99);f.events.push_back("route");return f.route;}};
struct NetworkController{static constexpr int LOCAL_NET_ID=99;};
struct XfrmController{static Status Init(){f.events.push_back("xfrm");return {f.xfrm};}};
namespace gta3xlwifi{
struct SocketPolicyProjection{
 explicit SocketPolicyProjection(int&){f.events.push_back("construct");}
 int prepareForControllerStartup(){f.events.push_back("lease");if(!f.lease)f.held=true;return f.lease;}
 int startWithAccounting(const std::vector<std::string>& p){assert(f.held&&p==std::vector<std::string>{"REAL_FACTORY"});f.events.push_back("owner");return f.owner;}
};}
std::unique_ptr<gta3xlwifi::SocketPolicyProjection> gta3xlwifiPolicyOwner;
struct Controllers{BandwidthController bandwidthCtrl;int iptablesRestoreCtrl=0;void init();gta3xlwifi::SocketPolicyProjection* gta3xlwifiPolicy()const;
 int initIptablesRules(){assert(!f.legacy||f.held);f.events.push_back("roots");return f.roots;}};
'''+get+'\n'+init+r'''
}
int main(){using namespace android::net;unsigned cases=0;
 for(bool legacy:{false,true})for(int stage=0;stage<=6;stage++)for(int error:{-EIO,1}){
  f=Fixture{};f.legacy=legacy;gta3xlwifiPolicyOwner.reset();int expected=0;
  if(stage==1&&legacy){f.lease=error;expected=5;}
  if(stage==2){f.roots=error;expected=1;}
  if(stage==3){f.flush=error;expected=2;}
  if(stage==4&&legacy){f.owner=error;expected=6;}
  if(stage==5){f.route=error;expected=3;}
  if(stage==6){f.xfrm=error;expected=4;}
  Controllers c;int status=0;try{c.init();}catch(Exit e){status=e.code;}assert(status==expected);
  std::vector<std::string> wanted;
  if(legacy){wanted={"construct","lease"};if(expected==5)goto compare;}
  wanted.push_back("roots");if(expected==1)goto compare;
  wanted.push_back(legacy?"flush":"stock");if(expected==2)goto compare;
  if(legacy){wanted.push_back("factory");wanted.push_back("owner");if(expected==6)goto compare;}
  wanted.push_back("route");if(expected==3)goto compare;wanted.push_back("xfrm");
 compare:
  assert(f.events==wanted);assert(bool(c.gta3xlwifiPolicy())==legacy);if(legacy&&expected!=5)assert(f.held);
  if(legacy&&stage>=3){if(expected==2)assert(c.bandwidthCtrl.mGlobalAlertBytes==5&&c.bandwidthCtrl.mSharedQuotaBytes==7&&!c.bandwidthCtrl.mSharedQuotaIfaces.empty());else assert(c.bandwidthCtrl.mGlobalAlertBytes==0&&c.bandwidthCtrl.mSharedQuotaBytes==0&&c.bandwidthCtrl.mQuotaIfaces.empty());}
  if(legacy&&expected==0){auto count=f.events.size();try{c.init();assert(false);}catch(Exit e){assert(e.code==5);}assert(f.events.size()==count&&f.held);}
  ++cases;
 }
 f=Fixture{};f.held=true;BandwidthController b;assert(b.prepareGta3xlwifiBandwidthControl()==0);assert(f.flushText==Join(IPT_FLUSH_COMMANDS,'\n'));assert(f.flushText.find("bpf")==std::string::npos);++cases;
 printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all',str(O/'test.cpp'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
paths=[Path(__file__),helper,O/'test.cpp',a.guard_source/'Controllers.cpp',A/'Controllers.cpp',A/'Controllers.h',*[S/n for n in ['Controllers.cpp','Controllers.h','BandwidthController.cpp','BandwidthController.h']],B/'BandwidthController.cpp',B/'BandwidthController.h']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(re.fullmatch(r'passed_cases=(\d+)\n',x.stdout)[1]),'stock_bandwidth_prefix_unchanged':True,'controller_and_bandwidth_layout_unchanged':True,'bandwidth_base_sha256':{n:sha(B/n) for n in ['BandwidthController.cpp','BandwidthController.h']},'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
