#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual transport regression and UID-delete commands with explicit driver fixtures."""
import argparse,ast,fcntl,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
reference=Path(__file__).with_name('test-qtaguid-transport.py');tree=ast.parse(reference.read_text());code=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TEST' for t in n.targets))
# Replay the current transport fixture, including its already-established
# close-on-passive behavior, rather than the older pre-quarantine expectations.
current=reference.with_name('test-socket-tagger-transport24.py')
current_tree=ast.parse(current.read_text())
extra=next(ast.literal_eval(n.value) for n in current_tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='extra' for t in n.targets))
code=code.replace('CHECK(t.untagSocket(fd)==-EOPNOTSUPP); CHECK(writes==before);','CHECK(t.untagSocket(fd)==-ENOTCONN); CHECK(writes==before&&!t.connected());',1)
code=code.replace('contents[tracking]="N\\n"; CHECK(t.tagSocket(fd,1,1)==0);','contents[tracking]="N\\n"; CHECK(t.tagSocket(fd,1,1)==-ENOTCONN&&!t.connected());',1)
needle='    CHECK(files.empty() && openedDevice==0);\n    std::cout';assert code.count(needle)==1;code=code.replace(needle,extra+needle)
# Existing socket commands retain their exact real FD validation; only d0UID
# commands take the separate new no-FD branch in the wrapped proc boundary.
needle='    int stable=-1; char c=0;';assert code.count(needle)==1
code=code.replace(needle,'''    if(text.rfind("d ",0)==0){unsigned zero=99,uid=0;char tail=0;
      CHECK(sscanf(text.c_str(),"d %u %u%c",&zero,&uid,&tail)==2&&zero==0&&uid<=INT_MAX);
      commands.push_back(text);return shortWrite?static_cast<ssize_t>(size)-1:static_cast<ssize_t>(size);
    }
'''+needle)
code=code.replace('int main() {','static void previousUidTransportTests() {',1)
code+=r'''
int main(){previousUidTransportTests();int begin=checks;
 reset();{QtaguidTransport t;CHECK(t.deleteUidTags(123)==-ENOTCONN&&writes==0);CHECK(t.deleteUidTags(UINT32_MAX)==-EINVAL&&writes==0);CHECK(!t.start());CHECK(t.deleteUidTags(uint32_t(INT_MAX)+1)==-EINVAL&&writes==0);for(uint32_t uid:{0u,123u,10001u,uint32_t(INT_MAX)}){CHECK(!t.deleteUidTags(uid));CHECK(commands.back()=="d 0 "+std::to_string(uid));}CHECK(t.connected()&&writes==4);t.stop();CHECK(t.deleteUidTags(123)==-ENOTCONN&&writes==4);}
 reset();{QtaguidTransport t;CHECK(!t.start());writeEintr=3;CHECK(!t.deleteUidTags(123)&&writes==4&&commands.size()==1&&commands[0]=="d 0 123");}
 for(int error:{EIO,EPERM,ENODEV}){reset();QtaguidTransport t;CHECK(!t.start());writeError=error;CHECK(t.deleteUidTags(123)==-error&&!t.connected());CHECK(t.deleteUidTags(123)==-ENOTCONN&&writes==1);}
 reset();{QtaguidTransport t;CHECK(!t.start());shortWrite=true;CHECK(t.deleteUidTags(123)==-EIO&&!t.connected()&&writes==1);CHECK(t.deleteUidTags(123)==-ENOTCONN&&writes==1);}
 reset();{QtaguidTransport t;CHECK(!t.start());contents[passive]="Y\n";CHECK(t.deleteUidTags(123)==-EOPNOTSUPP&&!t.connected()&&writes==0);}
 reset();{QtaguidTransport t;CHECK(!t.start());std::vector<std::thread>threads;for(int i=0;i<8;i++)threads.emplace_back([&]{assert(!t.deleteUidTags(123));});for(auto&th:threads)th.join();CHECK(writes==8&&commands.size()==8&&t.connected());}
 CHECK(files.empty()&&openedDevice==0);std::cout<<"uid_cleanup_transport_checks="<<checks-begin<<" total_checks="<<checks<<"\n";return 0;
}
'''
(O/'test.cpp').write_text('#include <algorithm>\n'+code)
command=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fno-omit-frame-pointer','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(S/'Gta3xlwifiQtaguidTransport.cpp'),str(O/'test.cpp'),'-o',str(O/'test')]
command+=['-Wl,--wrap='+x for x in ('open','close','read','__read_chk','write','fstat','fstatfs','getsockopt','ioctl')]
x=subprocess.run(command,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.stdout,x.stderr);m=re.search(r'uid_cleanup_transport_checks=(\d+) total_checks=(\d+)\n$',x.stdout);assert m
files=[Path(__file__),reference,current,O/'test.cpp',*[p for p in S.rglob('*') if p.is_file()]];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'total_checks':int(m[2]),'uid_cleanup_transport_checks':int(m[1]),'command':command,'inputs_sha256':{str(p):sha(p) for p in files},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
