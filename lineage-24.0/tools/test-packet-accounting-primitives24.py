#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual shared-lease packet primitive negotiation with syscall fixtures.

Missing storage OR compiled packet producers fails closed. No map, rule, release,
network readiness or device runtime is manufactured by these fixture tests.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();prior=json.loads((R/'report.json').read_text());assert prior['passed'] and sha(R/'test.cpp')==prior['inputs_sha256'][str(R/'test.cpp')]
code=(R/'test.cpp').read_text().split('int main(){',1)[0].replace('extern "C" int __wrap_ioctl(', 'extern "C" int underlyingIoctl(',1)
code+=r'''
#include <thread>
static unsigned featureCalls,featureRetries;static int featureError;
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);if(cmd==GTA3XLWIFI_UID_FEATURES){++featureCalls;if(featureRetries){--featureRetries;errno=EINTR;return -1;}if(featureError){errno=featureError<0?0:featureError;return -1;}}return underlyingIoctl(fd,cmd,arg);}
static void resetPrimitive(){resetEvents();featureCalls=featureRetries=0;featureError=0;}
int main(){
 resetPrimitive();{NetpolicyLease l;C(l.requirePacketAccountingPrimitives()==-ENOTCONN&&featureCalls==0);}
 for(int missing:{0,4095,4096,8191,8192,12287}){resetPrimitive();features=missing;NetpolicyLease l;C(l.start()==0);C(l.requirePacketAccountingPrimitives()==-EOPNOTSUPP&&files.empty()&&held&&featureCalls==1);}
 for(int available:{12288,16383,16383|(1<<20)}){resetPrimitive();features=available;NetpolicyLease l;C(l.start()==0);C(l.requirePacketAccountingPrimitives()==0&&held&&files.size()==1&&opens==1);C(l.release()==0&&!held);C(l.requirePacketAccountingPrimitives()==0&&!held&&files.size()==1&&opens==1);}
 for(int error:{EIO,ENOTTY,EPERM,EOPNOTSUPP,-1}){resetPrimitive();features=16383;featureError=error;NetpolicyLease l;C(l.start()==0);C(l.requirePacketAccountingPrimitives()==-(error<0?EIO:error)&&files.empty()&&held);}
 resetPrimitive();features=16383;featureRetries=3;{NetpolicyLease l;C(l.start()==0);C(l.requirePacketAccountingPrimitives()==0&&featureCalls==4&&held&&files.size()==1);}
 resetPrimitive();features=16383;{NetpolicyLease l;C(l.start()==0);std::vector<std::thread> tasks;for(int i=0;i<16;i++)tasks.emplace_back([&]{assert(l.requirePacketAccountingPrimitives()==0);});for(auto&t:tasks)t.join();C(featureCalls==16&&opens==1&&held&&files.size()==1);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(S/'Gta3xlwifiNetpolicyLease.cpp'),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+n for n in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=30
paths=[Path(__file__),R/'report.json',R/'test.cpp',S/'Gta3xlwifiNetpolicyLease.cpp',S/'Gta3xlwifiNetpolicyLease.h',*[p for p in (S/'linux/netfilter').glob('*.h')],O/'test.cpp'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
