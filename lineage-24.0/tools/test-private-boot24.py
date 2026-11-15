#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual held-provider adapter and main startup fragment with boundary fixtures.

Controller/transport/library/Netlink dependencies are fixtures. Main/DNS/oneshot
source outside explicit initialization changes remains identical to the baseline.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
provider=(S/'Gta3xlwifiHeldProvider.cpp').read_text();main=(S/'main.cpp').read_text();old=(S/'main.cpp.reference').read_text()
def extract(text,needle):
 start=text.index(needle);opening=text.index('{',start);depth=1;end=opening+1
 while depth:
  depth+=(text[end]=='{')-(text[end]=='}');end+=1
 return text[start:end]
oneshot=extract(main,'    if ((argc == 2) && !strcmp(argv[1], "oneshot"))')
original_oneshot=extract(old,'    if ((argc == 2) && !strcmp(argv[1], "oneshot"))')
main=main.replace(oneshot,original_oneshot,1)

start=main.index('    const bool legacy = android::base::GetBoolProperty(');end=main.index('    NetlinkManager *nm',start);replacement=main[start:end];old_start=old.index('    std::string cg2_path;');old_end=old.index('    NetlinkManager *nm',old_start)
wrapped='    if (!legacy) {\n';wrapped_start=replacement.index(wrapped)+len(wrapped);wrapped_end=replacement.rindex('    }\n');inner=replacement[wrapped_start:wrapped_end];assert ''.join(line[4:] if line.startswith('    ') else line for line in inner.splitlines(True))==old[old_start:old_end]
needle='    gCtls->init();\n';begin=main.index(needle);finish=main.index('    if (nm->start())',begin);addition=main[begin:finish];assert addition.startswith(needle)
recovered=main.replace('#include "Gta3xlwifiHeldProvider.h"\n#include <android-base/properties.h>\n','',1).replace(replacement,old[old_start:old_end],1).replace(addition,needle+'\n',1);assert recovered==old,'Unexpected main/DNS/oneshot source change'
fragment=main[start:main.index('    std::unique_ptr<NFLogListener>',start)]
body=provider[provider.index('namespace android::net::gta3xlwifi {'):]
code=r'''
#include "NetdUpdatablePublic.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
struct Exit{int code;};[[noreturn]]void testExit(int n){throw Exit{n};}
#define exit testExit
#define ALOGE(...) ((void)0)
struct Fixture{bool legacy=false,cgroup=true,netlink=true;int bpf=0,library=0,tagStart=0,firstVerify=0,secondVerify=0,nmStart=0,dns=0;unsigned checks=0,tags=0,untags=0,tagStops=0,ownerStops=0;std::vector<std::string> events;} f;
struct Logger{void info(const char*){}}gLog;
constexpr const char*CGROUPV2_HIERARCHY_NAME="v2";
bool CgroupGetControllerPath(const char*,std::string*out){f.events.push_back("cgroup");*out="/real/cgroup";return f.cgroup;}
int libnetd_updatable_init(const char*p){assert(!strcmp(p,"/real/cgroup")||!strcmp(p,"/sys/fs/cgroup"));f.events.push_back("bpf");return f.bpf;}
static NetdGta3xlwifiCallbacks installed{};
int resolv_set_gta3xlwifi_policy(int (*callback)(uid_t,bool)){f.events.push_back("dns-register");assert(callback);assert(callback(UINT32_MAX,false)==-EINVAL);assert(callback(10001,false)==-EAGAIN);return f.dns;}
int libnetd_updatable_init_gta3xlwifi(const NetdGta3xlwifiCallbacks*c){assert(c&&c->version==1&&c->size==sizeof(*c));f.events.push_back("library");if(f.library)return f.library;int result=c->initialize_held();if(!result)installed=*c;return result;}
struct NetlinkManager{static NetlinkManager*Instance(){f.events.push_back("netlink-instance");static NetlinkManager n;return f.netlink?&n:nullptr;}int start(){f.events.push_back("netlink-start");return f.nmStart;}};
namespace android::base{bool GetBoolProperty(const char*p,bool fallback){assert(!strcmp(p,"ro.gta3xlwifi.legacy_networking")&&!fallback);return f.legacy;}}
namespace android::net::gta3xlwifi{
struct QtaguidTransport{bool live=false;int start(){f.events.push_back("tag-start");if(!f.tagStart)live=true;return f.tagStart;}void stop(){live=false;++f.tagStops;f.events.push_back("tag-stop");}};
struct SocketPolicyProjection{int isNetworkingBlocked(int32_t uid,bool metered){assert(uid==10001&&!metered);return -EAGAIN;}int verifyHeldProviderStartup(){f.events.push_back("verify");return ++f.checks==1?f.firstVerify:f.secondVerify;}void stop(){++f.ownerStops;f.events.push_back("owner-stop");}int tagSocket(QtaguidTransport&t,int fd,uint32_t value,int32_t charge,int32_t real){assert(t.live&&fd==9&&value==7&&charge==123&&real==456);++f.tags;return -EAGAIN;}int untagSocket(QtaguidTransport&t,int fd){assert(t.live&&fd==9);++f.untags;return -EAGAIN;}};
}
namespace android::net{struct Controllers{gta3xlwifi::SocketPolicyProjection policy;void init(){f.events.push_back("controllers");}gta3xlwifi::SocketPolicyProjection*gta3xlwifiPolicy(){return f.legacy?&policy:nullptr;}};}
'''+body+r'''
android::net::Controllers*gCtls=nullptr;
static int preflight(int argc,const char*argv[]){
'''+oneshot+r'''
return 88;
}
static void startup(){
'''+fragment+r'''
}
static void reset(){using namespace android::net::gta3xlwifi;owner=nullptr;transport.live=false;delete gCtls;gCtls=nullptr;installed={};f=Fixture{};}
int main(){unsigned cases=0;using namespace android::net::gta3xlwifi;
 for(bool legacy:{false,true})for(unsigned fault=0;fault<11;fault++){
  reset();f.legacy=legacy;int expected=0;
  if(fault==1&&!legacy){f.cgroup=false;expected=1;}
  if(fault==2&&!legacy){f.bpf=-EIO;expected=1;}
  if(fault==3){f.netlink=false;expected=1;}
  if(fault==4&&legacy){f.library=-EOPNOTSUPP;expected=1;}
  if(fault==5&&legacy){f.firstVerify=-EIO;expected=1;}
  if(fault==6&&legacy){f.tagStart=-EBUSY;expected=1;}
  if(fault==7&&legacy){f.secondVerify=-EPROTO;expected=1;}
  if(fault==8){f.nmStart=-EIO;expected=1;}
  if(fault==10&&legacy){f.dns=-EIO;expected=1;}
  int result=0;try{startup();}catch(Exit e){result=e.code;}assert(result==expected);
  if(!legacy){assert(!owner&&!transport.live&&!installed.initialize_held&&!f.checks);assert(f.events[0]=="cgroup");}
  else{for(auto&e:f.events)assert(e!="bpf"&&e!="cgroup");assert(f.events[0]=="netlink-instance");if((fault>=4&&fault<=7)||fault==10)assert(!owner&&!transport.live&&f.tagStops==1&&f.ownerStops==1);if(!expected){assert((f.events==std::vector<std::string>{"netlink-instance","controllers","library","verify","tag-start","verify","dns-register","netlink-start"}));auto count=f.events.size();assert(initializeHeldProvider(*gCtls)==-EALREADY&&f.events.size()==count);assert(installed.tag_socket(9,7,123,456)==-EAGAIN&&f.tags==1);assert(installed.untag_socket(9)==-EAGAIN&&f.untags==1);assert(installed.tag_socket(9,7,UINT32_MAX,456)==-EINVAL&&f.tags==1);assert(installed.tag_socket(9,7,123,UINT32_MAX)==-EINVAL&&f.tags==1);}}
  ++cases;
 }
 const char*args[]={"netd","oneshot"};
 for(bool legacy:{false,true})for(unsigned fault=0;fault<7;++fault){
  reset();f.legacy=legacy;
  if(fault==1)f.library=-EIO;
  if(fault==2)f.firstVerify=-EIO;
  if(fault==3)f.tagStart=-EIO;
  if(fault==4)f.secondVerify=-EIO;
  if(fault==5)f.dns=-EIO;
  if(fault==6)f.bpf=-EIO;
  int result=preflight(2,args);
  assert(result==(legacy?((fault>=1&&fault<=5)?1:0):(fault==6?-EIO:0)));
  assert(!owner&&!transport.live&&!f.nmStart);
  for(const auto&e:f.events)assert(e!="netlink-instance"&&e!="netlink-start");
  if(legacy){assert(f.events.front()=="controllers");assert(f.ownerStops==1&&f.tagStops==1);}
  else assert(f.events==std::vector<std::string>{"bpf"});
  ++cases;
 }
 reset();assert(preflight(1,args)==88&&f.events.empty());++cases;
 reset();android::net::Controllers c;assert(initializeHeldProvider(c)==-EOPNOTSUPP&&!owner&&!transport.live);++cases;reset();printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(S),str(O/'test.cpp'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m
paths=[Path(__file__),O/'test.cpp',*[S/n for n in ['main.cpp','main.cpp.reference','Gta3xlwifiHeldProvider.cpp','Gta3xlwifiHeldProvider.h','NetdUpdatablePublic.h','Gta3xlwifiDnsPolicy.h']]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'original_main_DNS_oneshot_outside_initialization_unchanged':True,'actual_private_init_before_Netlink_and_Binder':True,'actual_private_oneshot_no_listeners_closes_held_owner':True,'DNS_registration_after_held_library_before_listeners':True,'failed_DNS_registration_stops_owner_and_transport':True,'failed_init_closes_transport_and_owner':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
