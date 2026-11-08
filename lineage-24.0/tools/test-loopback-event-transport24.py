#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual loopback-event consume transport, host syscall and malformed stream fixtures.

Includes real UID/LNA transport regressions. Queue is modeled; no real packets,
Binder delivery, metrics worker startup or whole-network readiness.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-local-network-transport24.py');subprocess.run(['python3',str(helper),'--source',str(S),'--output',str(O/'lna-regression')],check=True)
code=(O/'lna-regression/test.cpp').read_text().split('int main(){',1)[0].replace('extern "C" int __wrap_ioctl(', 'extern "C" int image_ioctl(')
code+=r'''
#include <linux/netfilter/gta3xlwifi_loopback.h>
using EWire=gta3xlwifi_loopback_event;using Batch=NetpolicyLease::LoopbackBatch;
std::vector<EWire> eventQueue;uint64_t lostTotal=0;unsigned eventCalls=0,eventFaultAt=0,eventFault=0,eventErrorAt=0;int eventError=0,eventAck=0;bool consumeError=false,appendAtConsume=false;
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
 va_list args;va_start(args,cmd);unsigned long arg=va_arg(args,unsigned long);va_end(args);
 if(cmd!=GTA3XLWIFI_LOOPBACK_GET_EVENTS)return image_ioctl(fd,cmd,arg);
 assert(files.count(fd)&&files.at(fd).path==node&&arg);++eventCalls;
 if(eventCalls==eventErrorAt&&!consumeError){errno=eventError;return -1;}
 auto*t=reinterpret_cast<gta3xlwifi_loopback_transfer*>(arg);assert(t->version==1&&t->count<=512&&bool(t->count)==bool(t->entries));
 auto*buffer=reinterpret_cast<EWire*>(static_cast<uintptr_t>(t->entries));bool consume=t->count;
 if(consume){assert(!eventQueue.empty()&&t->first_sequence==eventQueue.front().sequence);unsigned count=std::min(size_t(t->count),eventQueue.size());memcpy(buffer,eventQueue.data(),count*sizeof(EWire));eventQueue.erase(eventQueue.begin(),eventQueue.begin()+count);t->count=count;if(appendAtConsume)eventQueue.push_back({10002,110002,0,0,999,buffer[count-1].sequence+1,lostTotal});}
 else {t->count=eventQueue.size();t->first_sequence=eventQueue.empty()?0:eventQueue.front().sequence;}
 t->lost_events=lostTotal;
 if(eventCalls==eventErrorAt){errno=eventError;return -1;}
 if(eventCalls==eventFaultAt){switch(eventFault){
  case 1:t->version=2;break;case 2:t->count=513;break;case 3:t->entries=17;break;case 4:++t->first_sequence;break;case 5:t->first_sequence=0;break;case 6:t->lost_events=0;break;
  case 7:buffer[0].reserved=1;break;case 8:buffer[0].result=2;break;case 9:buffer[0].receiver_uid=buffer[0].sender_uid;break;case 10:++buffer[0].sequence;break;case 11:buffer[0].lost_events=lostTotal+1;break;case 12:buffer[1].sequence=buffer[0].sequence;break;case 13:buffer[1].lost_events=0;break;case 14:--t->count;break;default:assert(false);
 }}return eventAck;
}
EWire ewire(uint64_t seq,uint64_t lost=0){return {10001,110001,1,0,1000000000,seq,lost};}
void resetEvents(){resetLna();features=255;eventQueue.clear();lostTotal=0;eventCalls=eventFaultAt=eventFault=eventErrorAt=0;eventError=eventAck=0;consumeError=appendAtConsume=false;}
Batch sentinelEvents(){return {{{77,88,1,22,33,44}},555};}
bool untouchedEvents(const Batch&v){return v.events.size()==1&&v.events[0].senderUid==77&&v.events[0].receiverUid==88&&v.events[0].sequence==33&&v.lostEvents==555;}
int main(){
 static_assert(sizeof(gta3xlwifi_loopback_transfer)==32&&sizeof(EWire)==40);static_assert(GTA3XLWIFI_LOOPBACK_GET_EVENTS==0xc0206759);
 resetEvents();{NetpolicyLease l;Batch v=sentinelEvents();C(l.readLoopbackEvents(nullptr)==-EINVAL&&eventCalls==0);C(l.readLoopbackEvents(&v)==-ENOTCONN&&untouchedEvents(v));C(l.start()==0);C(l.readLoopbackEvents(&v)==0&&v.events.empty()&&v.lostEvents==0&&held);eventQueue={ewire(100),ewire(101)};lostTotal=10;eventQueue[1].boottime_ns=999;C(l.readLoopbackEvents(&v)==0&&v.events.size()==2&&v.events[0].sequence==100&&v.events[1].sequence==101&&v.events[0].lostEvents==0&&v.lostEvents==10&&eventQueue.empty());eventQueue={ewire(102,9)};C(l.readLoopbackEvents(&v)==0&&v.events[0].sequence==102&&v.events[0].lostEvents==9);C(l.release()==0&&!held);eventQueue={ewire(103,10)};C(l.readLoopbackEvents(&v)==0&&!held&&v.events[0].sequence==103);}
 for(int missing:{0,7,127}){resetEvents();features=missing;NetpolicyLease l;Batch v=sentinelEvents();C(l.start()==0);C(l.readLoopbackEvents(&v)==-EOPNOTSUPP&&untouchedEvents(v)&&files.empty()&&held&&eventCalls==0);}
 resetEvents();features=128;{NetpolicyLease l;Batch v;C(l.start()==0&&l.readLoopbackEvents(&v)==0&&v.events.empty());}
 for(unsigned fault:{1u,2u,3u,5u}){resetEvents();eventQueue={ewire(10),ewire(11)};eventFaultAt=1;eventFault=fault;NetpolicyLease l;Batch v=sentinelEvents();C(l.start()==0);C(l.readLoopbackEvents(&v)==-EPROTO&&untouchedEvents(v)&&eventQueue.size()==2&&files.empty()&&held);}
 for(unsigned fault:{1u,2u,3u,4u,5u,6u,7u,8u,9u,10u,11u,12u,13u,14u}){resetEvents();eventQueue={ewire(10,1),ewire(11,1)};lostTotal=2;eventFaultAt=2;eventFault=fault;NetpolicyLease l;Batch v=sentinelEvents();C(l.start()==0);C(l.readLoopbackEvents(&v)==-EPROTO&&untouchedEvents(v)&&eventQueue.empty()&&files.empty()&&held);}
 for(unsigned call:{1u,2u})for(int error:{EINTR,EFAULT,EIO,ESTALE})for(bool commit:{false,true}){
  resetEvents();eventQueue={ewire(10)};eventErrorAt=call;eventError=error;consumeError=commit;NetpolicyLease l;Batch v=sentinelEvents();C(l.start()==0);C(l.readLoopbackEvents(&v)==-error&&untouchedEvents(v)&&eventCalls==call&&files.empty()&&held);C(eventQueue.size()==(call==2&&commit?0:1));
 }
 resetEvents();eventQueue={ewire(10)};eventAck=1;{NetpolicyLease l;Batch v=sentinelEvents();C(l.start()==0);C(l.readLoopbackEvents(&v)==-EPROTO&&untouchedEvents(v)&&files.empty()&&held);}
 for(uint64_t next:{9ULL,10ULL,12ULL}){resetEvents();NetpolicyLease l;Batch v;C(l.start()==0);eventQueue={ewire(10)};C(l.readLoopbackEvents(&v)==0);eventQueue={ewire(next)};v=sentinelEvents();C(l.readLoopbackEvents(&v)==-EPROTO&&untouchedEvents(v)&&eventQueue.size()==1&&files.empty()&&held);}
 resetEvents();{NetpolicyLease l;Batch v;C(l.start()==0);eventQueue={ewire(10,5)};lostTotal=10;C(l.readLoopbackEvents(&v)==0);lostTotal=9;v=sentinelEvents();C(l.readLoopbackEvents(&v)==-EPROTO&&untouchedEvents(v)&&files.empty()&&held);}
 resetEvents();{NetpolicyLease l;Batch v;C(l.start()==0);eventQueue={ewire(10,5)};lostTotal=10;C(l.readLoopbackEvents(&v)==0);eventQueue={ewire(11,4)};v=sentinelEvents();C(l.readLoopbackEvents(&v)==-EPROTO&&untouchedEvents(v)&&files.empty()&&held);}
 resetEvents();{NetpolicyLease l;Batch v;C(l.start()==0);eventQueue={ewire(UINT64_MAX),ewire(0)};v=sentinelEvents();C(l.readLoopbackEvents(&v)==-EPROTO&&untouchedEvents(v)&&eventCalls==1&&files.empty()&&held);}
 resetEvents();{NetpolicyLease l;Batch v;C(l.start()==0);eventQueue={ewire(UINT64_MAX)};C(l.readLoopbackEvents(&v)==0&&v.events[0].sequence==UINT64_MAX);C(l.readLoopbackEvents(&v)==0&&v.events.empty());eventQueue={ewire(1)};v=sentinelEvents();C(l.readLoopbackEvents(&v)==-EPROTO&&untouchedEvents(v)&&files.empty()&&held);}
 resetEvents();{NetpolicyLease l;Batch v;C(l.start()==0);eventQueue={ewire(10)};C(l.readLoopbackEvents(&v)==0);l.stop();C(l.start()==0);eventQueue={ewire(99)};C(l.readLoopbackEvents(&v)==0&&v.events[0].sequence==99);}
 resetEvents();{NetpolicyLease l;Batch v;C(l.start()==0);eventQueue={ewire(10)};appendAtConsume=true;C(l.readLoopbackEvents(&v)==0&&v.events.size()==1&&eventQueue.size()==1);appendAtConsume=false;C(l.readLoopbackEvents(&v)==0&&v.events[0].sequence==11&&eventQueue.empty());}
 resetEvents();{NetpolicyLease l;C(l.start()==0);for(unsigned i=0;i<512;i++)eventQueue.push_back(ewire(i+1));std::vector<std::thread> threads;unsigned delivered=0;std::mutex sum;for(int i=0;i<16;i++)threads.emplace_back([&]{Batch v;assert(l.readLoopbackEvents(&v)==0);std::lock_guard<std::mutex>lock(sum);delivered+=v.events.size();});for(auto&t:threads)t.join();C(delivered==512&&eventQueue.empty()&&opens==1&&held);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(S/'Gta3xlwifiNetpolicyLease.cpp'),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=130
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,O/'test.cpp',S/'Gta3xlwifiNetpolicyLease.cpp',S/'Gta3xlwifiNetpolicyLease.h',*[S/'linux/netfilter'/n for n in ['gta3xlwifi_netpolicy.h','gta3xlwifi_uid_permissions.h','gta3xlwifi_local_network.h','gta3xlwifi_loopback.h']]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':x.stderr,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'uncertain_consume_never_retried':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual event consume transport, fatal UBSan syscall fixtures')
