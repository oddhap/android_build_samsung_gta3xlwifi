#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Linux syscall-fixture tests of the real isolated Android17 lease transport.

The actual C++ transport runs with GNU --wrap and fatal UBSan. Device, sysfs and
ioctl effects are fixtures; no real kernel/device/rules are opened or changed.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
code=r'''
#include "Gta3xlwifiNetpolicyLease.h"
#include <linux/netfilter/gta3xlwifi_netpolicy.h>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <string>
#include <thread>
#include <vector>
#include <cstdio>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>
using android::net::gta3xlwifi::NetpolicyLease;
unsigned cases=0;
#define C(x) do {++cases;assert(x);}while(0)
const std::string node="/dev/gta3xlwifi_netpolicy",identity="/sys/devices/virtual/misc/gta3xlwifi_netpolicy/dev";
struct Entry {std::string path;size_t offset=0;};std::map<int,Entry> files;
int nextfd=10000,opens=0,closes=0,openError=0,statError=0,fsError=0,readError=0;
int openEintr=0,readEintr=0,ioctlEintr=0,abi=1,ioctlError=0,stateOverride=-1,ack=0;
unsigned long errorCommand=0;bool held=true,wrongType=false,wrongSysfs=false,commitError=false,closeEintr=false;
uid_t nodeUid=0,sysfsUid=0;gid_t nodeGid=0;mode_t mode=0400;unsigned minorNumber=64;
std::string text="10:64\n";size_t chunk=100;
extern "C" int __real_close(int);
extern "C" int __real_fstat(int,struct stat*);
extern "C" int __wrap_open(const char* path,int flags,...){
 assert(flags&O_NOFOLLOW);assert(flags&O_CLOEXEC);assert((flags&O_ACCMODE)==O_RDONLY);
 assert(path==node||path==identity);
 if(openEintr){--openEintr;errno=EINTR;return -1;}
 if(openError){errno=openError;return -1;}
 if(path==node){assert(opens==0);++opens;held=true;}
 int fd=nextfd++;files.emplace(fd,Entry{path,0});return fd;
}
extern "C" int __wrap_close(int fd){
 auto i=files.find(fd);if(i==files.end())return __real_close(fd);
 bool isnode=i->second.path==node;if(isnode){++closes;--opens;held=true;}files.erase(i);
 if(isnode&&closeEintr){errno=EINTR;return -1;}return 0;
}
extern "C" int __wrap_fstat(int fd,struct stat* out){
 auto i=files.find(fd);if(i==files.end())return __real_fstat(fd,out);
 if(statError){errno=statError;return -1;}bool n=i->second.path==node;
 memset(out,0,sizeof(*out));out->st_mode=(n?S_IFCHR:S_IFREG)|(n?mode:0444);
 if(wrongType)out->st_mode=S_IFIFO;
 out->st_uid=n?nodeUid:sysfsUid;out->st_gid=n?nodeGid:0;out->st_rdev=makedev(10,minorNumber);return 0;
}
extern "C" int __wrap_fstatfs(int fd,struct statfs* out){
 assert(files.count(fd)&&files.at(fd).path==identity);if(fsError){errno=fsError;return -1;}
 memset(out,0,sizeof(*out));out->f_type=wrongSysfs?0x1234:0x62656572;return 0;
}
extern "C" ssize_t __wrap_read(int fd,void* buffer,size_t size){
 assert(files.count(fd)&&files.at(fd).path==identity);
 if(readEintr){--readEintr;errno=EINTR;return -1;}if(readError){errno=readError;return -1;}
 auto& e=files.at(fd);size_t n=std::min(std::min(size,chunk),text.size()-e.offset);
 memcpy(buffer,text.data()+e.offset,n);e.offset+=n;return n;
}
extern "C" ssize_t __wrap___read_chk(int fd,void* b,size_t n,size_t capacity){assert(n<=capacity);return __wrap_read(fd,b,n);}
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
 assert(files.count(fd)&&files.at(fd).path==node);
 va_list v;va_start(v,cmd);assert(va_arg(v,unsigned long)==0);va_end(v);
 assert(cmd>=0x6750&&cmd<=0x6753);
 if(ioctlEintr){--ioctlEintr;errno=EINTR;return -1;}
 if(ioctlError&&cmd==errorCommand){if(commitError&&cmd==GTA3XLWIFI_NETPOLICY_RELEASE)held=false;errno=ioctlError;return -1;}
 if(cmd==GTA3XLWIFI_NETPOLICY_ABI)return abi;
 if(cmd==GTA3XLWIFI_NETPOLICY_STATE)return stateOverride>=0?stateOverride:int(held);
 held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;
}
void reset(){assert(files.empty()&&opens==0);closes=0;openError=statError=fsError=readError=0;
 openEintr=readEintr=ioctlEintr=0;abi=1;ioctlError=0;errorCommand=0;stateOverride=-1;ack=0;
 held=true;wrongType=wrongSysfs=commitError=closeEintr=false;nodeUid=sysfsUid=nodeGid=0;mode=0400;minorNumber=64;text="10:64\n";chunk=100;}
int main(){
 reset();{NetpolicyLease l;bool b=false;C(l.hold()==-ENOTCONN);C(l.release()==-ENOTCONN);C(l.isHeld(&b)==-ENOTCONN&&!b);C(l.isHeld(nullptr)==-EINVAL);
 C(l.start()==0&&held&&opens==1);C(l.start()==-EALREADY&&opens==1);C(l.isHeld(&b)==0&&b);C(l.release()==0&&!held);C(l.isHeld(&b)==0&&!b);C(l.release()==0&&!held);C(l.hold()==0&&held);C(l.hold()==0&&held);l.stop();C(held&&closes==1&&opens==0);l.stop();C(closes==1);C(l.start()==0);}
 C(held&&files.empty()&&closes==2);
 for(auto s:std::vector<std::string>{"","10:64"," 10:64\n","10:64\nextra","10::64\n",":64\n","10:\n","-10:64\n","10:-64\n","11:64\n","42949672960:1\n","10:42949672960\n",std::string("10:64\0\n",7),std::string(32,'1')}){
 reset();text=s;NetpolicyLease l;C(l.start()<0&&files.empty()&&opens==0);}
 reset();chunk=1;openEintr=readEintr=ioctlEintr=1;{NetpolicyLease l;C(l.start()==0&&held);}C(files.empty()&&held);
 reset();wrongType=true;{NetpolicyLease l;C(l.start()==-ENODEV&&files.empty());}
 reset();wrongSysfs=true;{NetpolicyLease l;C(l.start()==-ENODEV&&files.empty());}
 reset();sysfsUid=1;{NetpolicyLease l;C(l.start()==-ENODEV&&files.empty());}
 reset();nodeUid=1;{NetpolicyLease l;C(l.start()==-ENODEV&&closes==1&&held);}
 reset();nodeGid=1;{NetpolicyLease l;C(l.start()==-ENODEV&&closes==1&&held);}
 reset();mode=0600;{NetpolicyLease l;C(l.start()==-ENODEV&&closes==1&&held);}
 reset();minorNumber=65;{NetpolicyLease l;C(l.start()==-ENODEV&&closes==1&&held);}
 reset();openError=EACCES;{NetpolicyLease l;C(l.start()==-EACCES&&files.empty());}
 reset();statError=EIO;{NetpolicyLease l;C(l.start()==-EIO&&files.empty());}
 reset();fsError=EIO;{NetpolicyLease l;C(l.start()==-EIO&&files.empty());}
 reset();readError=EIO;{NetpolicyLease l;C(l.start()==-EIO&&files.empty());}
 reset();abi=2;{NetpolicyLease l;C(l.start()==-EPROTO&&files.empty()&&held);}
 reset();stateOverride=0;{NetpolicyLease l;C(l.start()==-EPROTO&&files.empty()&&held);}
 reset();ioctlError=ENOTTY;errorCommand=GTA3XLWIFI_NETPOLICY_ABI;{NetpolicyLease l;C(l.start()==-ENOTTY&&files.empty()&&held);}
 reset();{NetpolicyLease l;C(l.start()==0);ack=1;C(l.release()==-EPROTO&&files.empty()&&held);C(l.hold()==-ENOTCONN);}
 reset();{NetpolicyLease l;C(l.start()==0);ioctlError=EIO;errorCommand=GTA3XLWIFI_NETPOLICY_RELEASE;commitError=true;C(l.release()==-EIO&&held&&closes==1&&files.empty());}
 reset();{NetpolicyLease l;C(l.start()==0);stateOverride=1;C(l.release()==-EPROTO&&held&&closes==1&&files.empty());}
 reset();{NetpolicyLease l;C(l.start()==0&&l.release()==0);stateOverride=0;C(l.hold()==-EPROTO&&held&&files.empty());}
 reset();{NetpolicyLease l;C(l.start()==0);bool b=false;stateOverride=2;C(l.isHeld(&b)==-EPROTO&&!b&&held&&files.empty());}
 reset();{NetpolicyLease l;C(l.start()==0&&l.release()==0);ioctlError=EPERM;errorCommand=GTA3XLWIFI_NETPOLICY_STATE;bool b=false;C(l.isHeld(&b)==-EPERM&&!b&&held&&files.empty());}
 reset();closeEintr=true;{NetpolicyLease l;C(l.start()==0&&l.release()==0);l.stop();C(closes==1&&held&&files.empty());l.stop();C(closes==1);}
 reset();{NetpolicyLease l;C(l.start()==0);std::vector<std::thread> threads;for(int i=0;i<16;i++)threads.emplace_back([&l,i]{assert((i%2?l.hold():l.release())==0);});for(auto& t:threads)t.join();C(l.hold()==0&&held);}
 C(files.empty()&&held&&closes==1);
 printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code)
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fno-omit-frame-pointer','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(S/'Gta3xlwifiNetpolicyLease.cpp'),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=30);(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',r.stdout);assert m and int(m[1])>=60
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),O/'test.cpp',S/'Gta3xlwifiNetpolicyLease.cpp',S/'Gta3xlwifiNetpolicyLease.h',S/'linux/netfilter/gta3xlwifi_netpolicy.h']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':r.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; actual transport with syscall fixtures, fatal UBSan')
