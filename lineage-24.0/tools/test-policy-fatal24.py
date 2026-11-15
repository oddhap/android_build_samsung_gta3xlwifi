#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay actual owner regressions and test fatal dispatch after held lease closure.

Actual Controllers termination is exercised with an explicit throwing process
boundary fixture; no host process, Android service or device is restarted.
"""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==26286
for name,h in r['inputs_sha256'].items():assert sha(Path(name))==h
for n in ['binder','com']:shutil.copytree(R/n,O/n)
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
code=(R/'test.cpp').read_text();assert code.count('int main(int argc,char**argv)')==1
code=code.replace('int main(int argc,char**argv)','static int previous_fatal_regressions(int argc,char**argv)')
code+=r'''
#include "Gta3xlwifiPolicyFatal.h"
static unsigned fatalCalls;static int fatalError;
static void captureFatal(int error){C(held&&files.empty());++fatalCalls;fatalError=error;}
static void otherFatal(int){assert(false);}
int main(int argc,char**argv){C(!previous_fatal_regressions(argc,argv));unsigned begin=cases;
 using android::net::gta3xlwifi::setPolicyFatalHandler;
 C(setPolicyFatalHandler(nullptr)==-EINVAL);C(!setPolicyFatalHandler(captureFatal));C(!setPolicyFatalHandler(captureFatal));C(setPolicyFatalHandler(otherFatal)==-EALREADY);
 resetNames();{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram)&&!owner.replace(desired(),0));C(!owner.suspendFrameworkClient()&&held);C(!fatalCalls);owner.stop();C(!fatalCalls);}C(!fatalCalls);
 resetNames();{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram)&&!owner.replace(desired(),0));auto invalid=desired();invalid.runtime.supplied=false;C(owner.replace(invalid,1)==-EINVAL&&!fatalCalls&&!held);owner.stop();C(!fatalCalls&&held&&files.empty());}
 for(int error:{EIO,EACCES,ENOTTY}){resetNames();unsigned before=fatalCalls;{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram)&&!owner.replace(desired(),0));nameError=error;NetpolicyLease::IfaceNamesSnapshot out;C(owner.readIfaceNames(&out)==-error);C(fatalCalls==before+1&&fatalError==-error&&held&&files.empty());owner.stop();C(fatalCalls==before+1);}C(fatalCalls==before+1);}
 resetNames();{unsigned before=fatalCalls;AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram)&&!owner.replace(desired(),0));nameFault=1;NetpolicyLease::IfaceNamesSnapshot out;C(owner.readIfaceNames(&out)==-EPROTO);C(fatalCalls==before+1&&fatalError==-EPROTO);}
 printf("fatal_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);old=next(Path(v).parent for v in r['command'] if v.endswith('/Gta3xlwifiSocketPolicyProjection.cpp'));cmd=[v.replace(str(R),str(O)).replace(str(old),str(S)) for v in r['command']]
def run(n,c):
 x=subprocess.run(c,capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/(n+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,(n,x.returncode,x.stdout[-3000:],x.stderr[-12000:]);return x.stdout
run('compile',cmd);output=run('test',[str(O/'test'),str(O/'names-wire.txt')]);m=re.search(r'fatal_cases=(\d+) total_cases=(\d+)\n$',output);assert m
# Compile the actual process-global registration/dispatch and Controllers handler,
# replacing only the process termination boundary with a noreturn exception.
policy=(S/'Gta3xlwifiSocketPolicyProjection.cpp').read_text();block=policy[policy.index('// Fatal owner recovery'):policy.index('#include "projection-guards.inc"')]
controllers=(S/'Controllers.cpp').read_text();handler=re.search(r'\[\[noreturn\]\] void privatePolicyFatal\(int error\) \{.*?\n\}',controllers,re.S)[0]
assert controllers.index('setPolicyFatalHandler(privatePolicyFatal)')<controllers.index('gta3xlwifiPolicyOwner = std::make_unique')
boundary='''#include <atomic>\n#include <cerrno>\n#include <cassert>\n#include "Gta3xlwifiPolicyFatal.h"\nstruct Termination{int code;};\n[[noreturn]] void fixtureExit(int code){throw Termination{code};}\nstatic unsigned logs;\n#define ALOGE(...) (++logs)\n#define _exit fixtureExit\nnamespace android::net::gta3xlwifi {\n'''+block+'\n}\n'+handler+'''
int main(){using namespace android::net::gta3xlwifi;
 assert(!setPolicyFatalHandler(privatePolicyFatal));
 assert(!setPolicyFatalHandler(privatePolicyFatal));
 try{dispatchPolicyFatal(-EIO);assert(false);}catch(const Termination&e){assert(e.code==1&&logs==1);}
 return 0;
}
'''
(O/'process-boundary.cpp').write_text(boundary);bc=[cmd[0],'-std=c++17','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(S),str(O/'process-boundary.cpp'),'-o',str(O/'process-boundary')];run('process-boundary-compile',bc);run('process-boundary',[str(O/'process-boundary')])
paths=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',O/'process-boundary.cpp',*[q for q in S.rglob('*') if q.is_file()]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[2]),'new_fatal_cases':int(m[1]),'held_and_lease_closed_before_dispatch':True,'normal_stop_suspend_and_invalid_input_do_not_dispatch':True,'actual_Controllers_exit_boundary_exercised':True,'commands':[cmd,bc],'inputs_sha256':{str(q):sha(q) for q in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(output.strip())
