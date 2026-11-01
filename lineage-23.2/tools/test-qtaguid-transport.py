#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Linux host tests of production qtaguid transport with wrapped driver syscalls.
Real socket/dup/getsockopt operations; proc/sysfs/device I/O is a fixture, never
real qtaguid traffic or kernel enforcement. Usage: test-qtaguid-transport.py STAGED_SERVER
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

TEST = r'''
#include "Gta3xlwifiQtaguidTransport.h"
#include "Gta3xlwifiQtaguidProtocol.h"
#include <cstdarg>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <vector>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>
using android::net::gta3xlwifi::QtaguidTransport;
static int checks=0;
#define CHECK(x) do { ++checks; if (!(x)) { std::cerr << "line " << __LINE__ << ": " #x << "\n"; abort(); } } while(0)
struct Entry { std::string path; size_t pos=0; };
static std::map<int,Entry> files;
static std::map<std::string,std::string> contents;
static int nextFd=10000, openedDevice=0, closedDevice=0, writes=0;
static int openError=0, statError=0, fsError=0, readError=0, writeError=0;
static int writeEintr=0, readEintr=0, openEintr=0, protocol=0;
static int ioctlError=0, ioctlResult=0, ioctlEintr=0;
static bool modeAck=false;
static bool shortWrite=false, wrongDevice=false, wrongMode=false, wrongProc=false, wrongSysfs=false;
static bool badLength=false;
static size_t chunk=100;
static std::vector<std::string> commands;
static int raceOriginal=-1, replacement=-1;
static ino_t expectedInode=0;
extern "C" int __real_close(int);
extern "C" int __real_fstat(int,struct stat*);
extern "C" int __real_getsockopt(int,int,int,void*,socklen_t*);
static bool device(const std::string& p) { return p=="/dev/xt_qtaguid"; }
static bool ctrl(const std::string& p) { return p=="/proc/net/xt_qtaguid/ctrl"; }
extern "C" int __wrap_open(const char* name,int flags,...) {
    std::string path=name;
    CHECK(flags & O_CLOEXEC); CHECK(flags & O_NOFOLLOW);
    if (openEintr) { --openEintr; errno=EINTR; return -1; }
    if (openError && (ctrl(path) || path.find("tag_tracking_passive")!=std::string::npos)) {
        errno=openError; return -1;
    }
    if (device(path)) {
        CHECK((flags&O_ACCMODE)==O_RDONLY);
        if(openedDevice) { errno=EBUSY; return -1; }
        ++openedDevice;
    } else if (ctrl(path)) CHECK((flags&O_ACCMODE)==O_WRONLY);
    else {
        CHECK((flags&O_ACCMODE)==O_RDONLY);
        if(!contents.count(path)) { errno=ENOENT; return -1; }
    }
    int fd=nextFd++; files.emplace(fd,Entry{path,0}); return fd;
}
extern "C" int __wrap_close(int fd) {
    auto it=files.find(fd);
    if(it==files.end()) return __real_close(fd);
    if(device(it->second.path)) { --openedDevice; ++closedDevice; modeAck=false; }
    files.erase(it); return 0;
}
extern "C" int __wrap_ioctl(int fd,unsigned long request,...) {
    CHECK(files.count(fd) && device(files.at(fd).path));
    CHECK(request==QTAGUID_SOCKET_OWNED_SESSION && request==0x7151);
    va_list args; va_start(args,request); unsigned long arg=va_arg(args,unsigned long); va_end(args); CHECK(arg==0);
    if(ioctlEintr) { --ioctlEintr; errno=EINTR; return -1; }
    if(ioctlError) { errno=ioctlError; return -1; }
    modeAck=(ioctlResult==0); return ioctlResult;
}
extern "C" int __wrap_fstat(int fd,struct stat* st) {
    auto it=files.find(fd); if(it==files.end()) return __real_fstat(fd,st);
    if(statError) { errno=statError; return -1; }
    memset(st,0,sizeof(*st));
    st->st_mode=device(it->second.path) ? S_IFCHR : S_IFREG;
    if(wrongMode) st->st_mode=S_IFIFO;
    st->st_rdev=makedev(10,wrongDevice?65:64); return 0;
}
extern "C" int __wrap_fstatfs(int fd,struct statfs* fs) {
    CHECK(files.count(fd)); if(fsError) { errno=fsError; return -1; }
    memset(fs,0,sizeof(*fs)); bool c=ctrl(files.at(fd).path);
    fs->f_type=c ? (wrongProc?0x1234:0x9fa0) : (wrongSysfs?0x1234:0x62656572);
    return 0;
}
extern "C" ssize_t __wrap_read(int fd,void* buf,size_t size) {
    CHECK(files.count(fd));
    if(readEintr) { --readEintr; errno=EINTR; return -1; }
    if(readError) { errno=readError; return -1; }
    auto& e=files.at(fd); auto& s=contents.at(e.path);
    size_t n=std::min({size,chunk,s.size()-e.pos});
    memcpy(buf,s.data()+e.pos,n); e.pos+=n; return static_cast<ssize_t>(n);
}
// Ubuntu's fortified libc redirects read to __read_chk. Preserve its bounds
// contract while wrapping the driver operation, not disabling fortification.
extern "C" ssize_t __wrap___read_chk(int fd,void* buf,size_t size,size_t capacity) {
    CHECK(size<=capacity); return __wrap_read(fd,buf,size);
}
extern "C" int __wrap_getsockopt(int fd,int level,int opt,void* val,socklen_t* length) {
    int r=__real_getsockopt(fd,level,opt,val,length);
    if(r==0 && protocol && opt==SO_PROTOCOL) *static_cast<int*>(val)=protocol;
    if(r==0 && badLength) *length=1;
    return r;
}
extern "C" ssize_t __wrap_write(int fd,const void* data,size_t size) {
    ++writes; CHECK(files.count(fd) && ctrl(files.at(fd).path)); CHECK(openedDevice==1); CHECK(modeAck);
    if(writeEintr) { --writeEintr; errno=EINTR; return -1; }
    if(writeError) { errno=writeError; return -1; }
    std::string text(static_cast<const char*>(data),size);
    int stable=-1; char c=0; CHECK(sscanf(text.c_str(),"%c %d",&c,&stable)==2);
    CHECK(fcntl(stable,F_GETFD)&FD_CLOEXEC);
    struct stat st{}; CHECK(__real_fstat(stable,&st)==0);
    if(expectedInode) CHECK(st.st_ino==expectedInode);
    if(raceOriginal>=0) {
        CHECK(stable!=raceOriginal); CHECK(__real_close(raceOriginal)==0);
        replacement=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
        CHECK(replacement==raceOriginal);
        struct stat other{}; CHECK(__real_fstat(replacement,&other)==0);
        CHECK(other.st_ino!=st.st_ino); CHECK(__real_fstat(stable,&st)==0);
        CHECK(st.st_ino==expectedInode); raceOriginal=-1;
    }
    commands.push_back(text); return shortWrite?static_cast<ssize_t>(size)-1:static_cast<ssize_t>(size);
}
static const char* passive="/sys/module/xt_qtaguid/parameters/passive";
static const char* tracking="/sys/module/xt_qtaguid/parameters/tag_tracking_passive";
static const char* identity="/sys/class/misc/xt_qtaguid/dev";
static void reset() {
    CHECK(files.empty() && openedDevice==0);
    contents={{passive,"N\n"},{tracking,"N\n"},{identity,"10:64\n"}};
    openError=statError=fsError=readError=writeError=0;
    openEintr=readEintr=writeEintr=protocol=0;
    shortWrite=wrongDevice=wrongMode=wrongProc=wrongSysfs=badLength=false;
    writes=closedDevice=0; chunk=100; commands.clear(); expectedInode=0;
    ioctlError=ioctlResult=ioctlEintr=0; modeAck=false;
}
static int sock(int family,int type) { int fd=socket(family,type|SOCK_CLOEXEC,0); CHECK(fd>=0); return fd; }
int main() {
    reset();
    { QtaguidTransport t; CHECK(t.tagSocket(-1,1,10001)==-ENOTCONN); CHECK(t.untagSocket(-1)==-ENOTCONN);
      int started=t.start(); if(started) std::cerr<<"start error "<<started<<" fake open fds "<<files.size()<<"\n";
      CHECK(started==0); CHECK(t.start()==-EALREADY);
      QtaguidTransport other; CHECK(other.start()==-EBUSY); CHECK(openedDevice==1);
      for(int family:{AF_INET,AF_INET6}) for(int type:{SOCK_STREAM,SOCK_DGRAM}) {
          int fd=sock(family,type); struct stat st{}; CHECK(fstat(fd,&st)==0); expectedInode=st.st_ino;
          CHECK(t.tagSocket(fd,0xffffffffu,INT_MAX)==0);
          char c=0; int stable=0; unsigned long long tag=0; unsigned uid=0; char extra=0;
          CHECK(sscanf(commands.back().c_str(),"%c %d %llu %u %c",&c,&stable,&tag,&uid,&extra)==4);
          CHECK(c=='t' && stable!=fd && tag==0xffffffff00000000ULL && uid==INT_MAX);
          CHECK(fcntl(stable,F_GETFD)==-1 && errno==EBADF);
          CHECK(t.tagSocket(fd,0,0)==0); CHECK(t.untagSocket(fd)==0);
          CHECK(commands.back()[0]=='u'); close(fd);
      }
      expectedInode=0; int fd=sock(AF_INET,SOCK_DGRAM);
      int before=writes; CHECK(t.tagSocket(fd,1,UINT32_MAX)==-EINVAL); CHECK(writes==before);
      CHECK(t.tagSocket(-1,0,0)==-EBADF); CHECK(writes==before);
      int unixfd=sock(AF_UNIX,SOCK_DGRAM); CHECK(t.tagSocket(unixfd,0,0)==-EAFNOSUPPORT); close(unixfd);
      int pipes[2]; CHECK(pipe(pipes)==0); CHECK(t.tagSocket(pipes[0],0,0)==-ENOTSOCK); close(pipes[0]); close(pipes[1]);
      protocol=IPPROTO_ICMP; CHECK(t.tagSocket(fd,1,1)==-EPROTONOSUPPORT); protocol=0;
      badLength=true; CHECK(t.tagSocket(fd,1,1)==-EPROTO); badLength=false; CHECK(writes==before);
      writeError=EPERM; CHECK(t.tagSocket(fd,1,1)==-EPERM); writeError=EINVAL;
      CHECK(t.untagSocket(fd)==-EINVAL); writeError=0;
      writeEintr=1; CHECK(t.tagSocket(fd,1,1)==0);
      contents[passive]="Y\n"; before=writes; CHECK(t.tagSocket(fd,1,1)==-EOPNOTSUPP); CHECK(writes==before);
      contents[passive]="N\n"; contents[tracking]="Y\n"; CHECK(t.untagSocket(fd)==-EOPNOTSUPP); CHECK(writes==before);
      contents[tracking]="N\n"; CHECK(t.tagSocket(fd,1,1)==0);
      close(fd);
    }
    CHECK(closedDevice==1);
    for(const char* name:{passive,tracking}) for(const std::string& bad:std::vector<std::string>{"Y\n","", "n\n","N","N\nN\n",std::string("N\0\n",3),std::string(40,'N')}) {
        reset(); contents[name]=bad; QtaguidTransport t; CHECK(t.start()<0); CHECK(writes==0);
    }
    for(const std::string bad:{"11:64\n","10:65:1\n",":64\n","10:\n","10:64", "10:42949672960\n","10:+64\n"}) {
        reset(); contents[identity]=bad; QtaguidTransport t; CHECK(t.start()<0); CHECK(writes==0);
    }
    for(int scenario=0;scenario<9;++scenario) {
        reset();
        if(scenario==0) openError=EACCES;
        if(scenario==1) statError=EIO;
        if(scenario==2) fsError=EPERM;
        if(scenario==3) readError=EIO;
        if(scenario==4) wrongSysfs=true;
        if(scenario==5) wrongProc=true;
        if(scenario==6) wrongDevice=true;
        if(scenario==7) wrongMode=true;
        if(scenario==8) contents.erase(passive);
        { QtaguidTransport t; CHECK(t.start()<0); CHECK(t.tagSocket(-1,1,1)==-ENOTCONN); }
        CHECK(files.empty() && openedDevice==0);
    }
    for(int error:{ENOTTY,EPERM,EOPNOTSUPP,EIO}) {
        reset(); ioctlError=error;
        { QtaguidTransport t; CHECK(t.start()==-error); CHECK(writes==0 && closedDevice==1); }
    }
    reset(); { QtaguidTransport t; ioctlResult=1; CHECK(t.start()==-EPROTO); CHECK(writes==0); }
    reset(); { QtaguidTransport t; chunk=1; openEintr=1; readEintr=1; ioctlEintr=1; CHECK(t.start()==0);
      int fd=sock(AF_INET,SOCK_DGRAM); shortWrite=true;
      CHECK(t.tagSocket(fd,1,1)==-EIO); CHECK(writes==1 && closedDevice==1);
      CHECK(t.tagSocket(fd,1,1)==-ENOTCONN); CHECK(writes==1); close(fd); }
    reset(); { QtaguidTransport t; CHECK(t.start()==0); int fd=sock(AF_INET,SOCK_DGRAM);
      struct stat st{}; CHECK(fstat(fd,&st)==0); expectedInode=st.st_ino; raceOriginal=fd;
      CHECK(t.tagSocket(fd,123,10001)==0); CHECK(replacement==fd); close(replacement); }
    reset(); { QtaguidTransport t; CHECK(t.start()==0); int fd=sock(AF_INET,SOCK_DGRAM);
      std::vector<std::thread> threads;
      for(int i=0;i<16;++i) threads.emplace_back([&t,fd,i]{ int r=t.tagSocket(fd,static_cast<uint32_t>(i),10001); assert(r==0); });
      for(auto& th:threads) { th.join(); }
      CHECK(writes==16 && commands.size()==16); close(fd); }
    CHECK(files.empty() && openedDevice==0);
    std::cout<<"PASS: "<<checks<<" transport/fixture assertions; real IPv4/IPv6 TCP/UDP and FD-reuse checks; mocked driver I/O only\n";
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('staged', type=Path)
    a = p.parse_args()
    if not sys.platform.startswith('linux'):
        p.error('Linux host required for GNU linker --wrap and proc/sysfs statfs types')
    source = a.staged.resolve()
    with tempfile.TemporaryDirectory(prefix='qtaguid-transport-test-') as d:
        d = Path(d)
        (d/'test.cpp').write_text('#include <algorithm>\n' + TEST)
        command = [os.environ.get('CXX', 'c++'), '-std=c++17', '-Wall', '-Wextra', '-Werror',
                   '-g', '-O1', '-fno-omit-frame-pointer', '-fsanitize=address,undefined', '-pthread',
                   '-I'+str(source), str(source/'Gta3xlwifiQtaguidTransport.cpp'), str(d/'test.cpp'),
                   '-o', str(d/'test')]
        command += ['-Wl,--wrap='+x for x in ('open','close','read','__read_chk','write','fstat','fstatfs','getsockopt','ioctl')]
        subprocess.run(command, check=True)
        subprocess.run([str(d/'test')], check=True)


if __name__ == '__main__':
    main()
