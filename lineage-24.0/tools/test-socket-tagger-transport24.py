#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real QtaguidTransport session/FD tests with mocked proc/sysfs/device I/O.

Replays prior real IPv4/IPv6 TCP/UDP, FD-reuse and threaded socket tests. A detected
passive/inaccessible transport now closes its session; recovery is explicit.
"""
import argparse,ast,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
helper=Path(__file__).with_name('test-qtaguid-transport.py');tree=ast.parse(helper.read_text());code=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TEST' for t in n.targets))
code=code.replace('CHECK(t.untagSocket(fd)==-EOPNOTSUPP); CHECK(writes==before);','CHECK(t.untagSocket(fd)==-ENOTCONN); CHECK(writes==before&&!t.connected());',1).replace('contents[tracking]="N\\n"; CHECK(t.tagSocket(fd,1,1)==0);','contents[tracking]="N\\n"; CHECK(t.tagSocket(fd,1,1)==-ENOTCONN&&!t.connected());',1)
needle='    CHECK(files.empty() && openedDevice==0);\n    std::cout';extra=r'''
    reset();{QtaguidTransport t;CHECK(!t.connected());CHECK(t.start()==0&&t.connected());t.stop();t.stop();CHECK(!t.connected()&&closedDevice==1);CHECK(t.untagSocket(-1)==-ENOTCONN);CHECK(t.start()==0&&t.connected());int fd=sock(AF_INET,SOCK_DGRAM);CHECK(t.tagSocket(-1,0,1)==-EBADF&&t.connected());CHECK(t.tagSocket(fd,0,1)==0);close(fd);}CHECK(closedDevice==2);
    for(const char* name:{passive,tracking})for(bool untag:{false,true}){reset();QtaguidTransport t;CHECK(t.start()==0);int fd=sock(AF_INET6,SOCK_DGRAM);contents[name]="Y\n";CHECK((untag?t.untagSocket(fd):t.tagSocket(fd,0,1))==-EOPNOTSUPP);CHECK(!t.connected()&&!writes&&closedDevice==1);contents[name]="N\n";CHECK(t.start()==0&&t.connected());CHECK(t.tagSocket(fd,0,1)==0);close(fd);}
''';assert needle in code;code=code.replace(needle,extra+needle,1);code='#include <algorithm>\n'+code;(O/'test.cpp').write_text(code)
cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(S/'Gta3xlwifiQtaguidTransport.cpp'),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+n for n in ['open','close','read','__read_chk','write','fstat','fstatfs','getsockopt','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1','ASAN_OPTIONS':'detect_leaks=1:halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'PASS: (\d+) transport/fixture assertions; real IPv4/IPv6 TCP/UDP and FD-reuse checks; mocked driver I/O only\n',x.stdout);assert m
paths=[Path(__file__),helper,O/'test.cpp',*[S/n for n in ['Gta3xlwifiSocketTagger.h','Gta3xlwifiQtaguidTransport.h','Gta3xlwifiQtaguidTransport.cpp','Gta3xlwifiQtaguidProtocol.h']]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'real_ipv4_ipv6_TCP_UDP_and_fd_reuse':True,'private_session_handshake_required':True,'failure_closes_no_automatic_recovery':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
