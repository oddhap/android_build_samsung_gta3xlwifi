#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual mainline provider dispatch with strict registration/lifetime fixtures.

BPF initialization and held/native callbacks are fixtures. Does not load BPF,
initialize the real provider or claim packet/service/device readiness.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=S/'NetdUpdatable.cpp';text=source.read_text();code=r'''
#include "NetdUpdatablePublic.h"
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <vector>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
struct Logger{template<class T>Logger&operator<<(const T&){return *this;}};
#define LOG(x) Logger{}
static unsigned bpfInit,bpfTags,bpfUntags;static bool bpfFail;
namespace android::base{void InitLogging(void*){}template<class T>struct Result{bool ok()const{return !bpfFail;}Logger error()const{return {};}};}
Logger&operator<<(Logger&l,const char*){return l;}
namespace android::net{struct BpfHandler{android::base::Result<void>init(const char*p){assert(p&&*p);++bpfInit;return {};}int tagSocket(int fd,uint32_t tag,uid_t charge,uid_t real){assert(fd==19&&tag==UINT32_MAX&&charge==123&&real==456);++bpfTags;return -EPERM;}int untagSocket(int fd){assert(fd==19);++bpfUntags;return -ENOENT;}};}
'''+text[text.index('static android::net::BpfHandler sBpfHandler;'):]+r'''
static unsigned cases,initCalls;static int initResult;static std::atomic<unsigned> tagCalls,untagCalls;
static NetdGta3xlwifiCallbacks*mutate;
static int initialize(){++initCalls;if(mutate){mutate->tag_socket=nullptr;mutate->size=0;}return initResult;}
static int tag(int fd,uint32_t value,uid_t charge,uid_t real){assert(fd==19&&value==UINT32_MAX&&charge==123&&real==456);++tagCalls;return -77;}
static int untag(int fd){assert(fd==19);++untagCalls;return -88;}
static NetdGta3xlwifiCallbacks valid(){return {1,sizeof(NetdGta3xlwifiCallbacks),initialize,tag,untag};}
static void reset(){sPrivateProvider=false;sInitialized=false;sCallbacks={};bpfInit=bpfTags=bpfUntags=initCalls=0;bpfFail=false;initResult=0;tagCalls=0;untagCalls=0;mutate=nullptr;}
#define T(x) do{++cases;assert(x);}while(0)
int main(){
 reset();T(libnetd_updatable_tagSocket(19,UINT32_MAX,123,456)==-EPERM&&bpfTags==1);T(libnetd_updatable_untagSocket(19)==-ENOENT&&bpfUntags==1);T(libnetd_updatable_init("/real/cgroup/path")==0&&bpfInit==1);auto c=valid();T(libnetd_updatable_init_gta3xlwifi(&c)==-EALREADY&&!initCalls);T(libnetd_updatable_init("/real/cgroup/path")==0&&bpfInit==2);
 for(unsigned fault=0;fault<7;fault++){reset();c=valid();const NetdGta3xlwifiCallbacks*p=&c;switch(fault){case 0:p=nullptr;break;case 1:c.version=2;break;case 2:--c.size;break;case 3:++c.size;break;case 4:c.initialize_held=nullptr;break;case 5:c.tag_socket=nullptr;break;case 6:c.untag_socket=nullptr;break;}T(libnetd_updatable_init_gta3xlwifi(p)==-EINVAL&&!initCalls&&!sInitialized&&!sPrivateProvider&&!bpfInit);}
 for(int error:{-EIO,-ENODEV,-EOPNOTSUPP,1}){reset();c=valid();initResult=error;T(libnetd_updatable_init_gta3xlwifi(&c)==(error<0?error:-EPROTO)&&initCalls==1&&!sInitialized&&!sPrivateProvider&&!bpfInit);initResult=0;T(libnetd_updatable_init_gta3xlwifi(&c)==0&&initCalls==2&&sPrivateProvider&&!bpfInit);}
 reset();c=valid();mutate=&c;T(libnetd_updatable_init_gta3xlwifi(&c)==0&&sPrivateProvider&&!bpfInit&&initCalls==1);T(libnetd_updatable_tagSocket(19,UINT32_MAX,123,456)==-77&&tagCalls==1&&!bpfTags);T(libnetd_updatable_untagSocket(19)==-88&&untagCalls==1&&!bpfUntags);c=valid();T(libnetd_updatable_init_gta3xlwifi(&c)==-EALREADY&&initCalls==1);T(libnetd_updatable_init("/real/cgroup/path")==-EBUSY&&!bpfInit);
 std::vector<std::thread> workers;for(unsigned i=0;i<32;i++)workers.emplace_back([]{for(unsigned n=0;n<100;n++){assert(libnetd_updatable_tagSocket(19,UINT32_MAX,123,456)==-77);assert(libnetd_updatable_untagSocket(19)==-88);}});for(auto&t:workers)t.join();T(tagCalls==3201&&untagCalls==3201&&!bpfTags&&!bpfUntags);
 reset();c=valid();int results[2];std::thread one([&]{results[0]=libnetd_updatable_init_gta3xlwifi(&c);}),two([&]{results[1]=libnetd_updatable_init_gta3xlwifi(&c);});one.join();two.join();T((results[0]==0&&results[1]==-EALREADY)||(results[1]==0&&results[0]==-EALREADY));T(initCalls==1&&!bpfInit);
 reset();pid_t child=fork();assert(child>=0);if(!child){rlimit limit{0,0};setrlimit(RLIMIT_CORE,&limit);bpfFail=true;libnetd_updatable_init("/real/cgroup/path");_exit(99);}int status=0;assert(waitpid(child,&status,0)==child);T(WIFSIGNALED(status)&&WTERMSIG(status)==SIGABRT);
 printf("passed_cases=%u concurrent_callback_calls=6400\n",cases);
}
'''
# Original log error stream requires a printable error result in the fixture.
code=code.replace('Logger error()const{return {};}','const char* error()const{return "BPF failure";}').replace('ret.error().message()','ret.error()')
(O/'test.cpp').write_text(code);cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(O/'test.cpp'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+) concurrent_callback_calls=6400\n',x.stdout);assert m
paths=[Path(__file__),source,S/'NetdUpdatablePublic.h',S/'libnetd_updatable.map.txt',O/'test.cpp'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'concurrent_callback_calls':6400,'legacy_init_never_calls_or_reports_BPF_init':True,'old_dispatch_preserved':True,'callbacks_copied_and_immutable_after_publication':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
