#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproduce the real oneshot null-global bug with actual main branch/restore helpers.

Controllers and property/provider/restore execution are explicit host fixtures;
this checks initialization identity and failure propagation, not Android networking.
The real provider checks, kernel HOLD, policy and boot failure guard are unchanged.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['composition','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();C=a.composition;O=a.output;assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def block(s,marker):
 start=s.index(marker);brace=s.index('{',start);depth=1;i=brace+1
 while depth:
  if s[i]=='{':depth+=1
  elif s[i]=='}':depth-=1
  i+=1
 return s[start:i]
helper_source=(C/'NetdConstants.cpp').read_text();helpers='\n'.join(block(helper_source,m) for m in ['int execIptablesRestoreWithOutput(', 'int execIptablesRestore('])
fixture=r'''
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
enum IptablesTarget { V4V6 };
static bool legacy;static int providerResult,stockResult,restoreResult;
static int initCount,restoreCount,providerCount,stockCount;
static void* observedController;
int execIptablesRestore(IptablesTarget,const std::string&);
namespace android { namespace net {
struct IptablesRestoreController { int execute(IptablesTarget,const std::string&,std::string*){restoreCount++;return restoreResult;} };
struct Controllers { IptablesRestoreController iptablesRestoreCtrl;void init(){initCount++;observedController=this;if(execIptablesRestore(V4V6,"fixture"))std::exit(23);} };
Controllers* gCtls=nullptr;
namespace gta3xlwifi {static int checkHeldProviderStartup(Controllers& c){providerCount++;assert(&c==gCtls);assert(observedController==gCtls);return providerResult;} }
} namespace base {static bool GetBoolProperty(const char*,bool){return legacy;} } }
using android::net::gCtls;
static int libnetd_updatable_init(const char*){stockCount++;return stockResult;}
#define ALOGE(...) do {} while(0)
'''
trailer=r'''
int main(int argc,char**argv){
 if(argc!=2)return 90;
 std::string mode=argv[1];legacy=mode!="stock-ok"&&mode!="stock-error";
 if(mode=="provider-error")providerResult=-EIO;
 if(mode=="stock-error")stockResult=-EPERM;
 if(mode=="restore-error")restoreResult=-EIO;
 const char*args[]={"netd","oneshot"};int r=actual_main(2,args);
 if(!legacy){assert(r==stockResult&&stockCount==1&&!initCount&&!providerCount&&!gCtls);}
 else {assert(r==(providerResult?1:0)&&!stockCount&&initCount==1&&restoreCount==1&&providerCount==1);delete gCtls;gCtls=nullptr;}
 printf("exit=%d init=%d restore=%d provider=%d stock=%d\n",r,initCount,restoreCount,providerCount,stockCount);return 0;
}
'''
results=[];rel='system/netd/server/main.cpp'
for kind in ['baseline','files']:
 source=(C/kind/rel).read_text();branch=block(source,'if ((argc == 2) && !strcmp(argv[1], "oneshot"))')
 cpp=O/(kind+'.cpp');cpp.write_text(fixture+helpers+'\nint actual_main(const int argc,const char*argv[]){\n'+branch+'\nreturn 82;\n}\n'+trailer)
 exe=O/kind;cmd=['g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(cpp),'-o',str(exe)];subprocess.run(cmd,check=True)
 for mode in (['legacy-ok'] if kind=='baseline' else ['legacy-ok','provider-error','stock-ok','stock-error','restore-error']):
  r=subprocess.run([str(exe),mode],capture_output=True,text=True)
  if kind=='baseline':assert r.returncode!=0 and 'null pointer' in r.stderr
  elif mode=='restore-error':assert r.returncode==23
  else:assert r.returncode==0,r.stderr
  results.append({'kind':kind,'mode':mode,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'actual_branch_sha256':hashlib.sha256(branch.encode()).hexdigest()})
report={'passed':True,'scope':__doc__,'original_null_global_reproduced':True,'fixed_global_identity_and_failure_propagation_passed':True,'source_sha256':{rel:sha(C/'files'/rel)},'unchanged_restore_helpers_sha256':sha(C/'NetdConstants.cpp'),'unchanged_controllers_source_sha256':sha(C/'Controllers.cpp'),'actual_restore_helpers_sha256':hashlib.sha256(helpers.encode()).hexdigest(),'cases':results,'real_Android_networking_not_executed':True,'policy_kernel_crypto_and_boot_failure_guards_changed':False,'flash_ready':False};(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS original null-global reproduction, fixed controller identity and retained error results')
