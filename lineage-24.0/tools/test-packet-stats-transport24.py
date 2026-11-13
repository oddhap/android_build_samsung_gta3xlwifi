#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile actual shared-lease packet-store transport with syscall wire/fault fixtures.

No actual packet hooks, kernel invocation, poll persistence or readiness claims.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
prior=json.loads((R/'report.json').read_text());assert prior['passed'] and sha(R/'test.cpp')==prior['inputs_sha256'][str(R/'test.cpp')]
code=(R/'test.cpp').read_text().split('int main(){',1)[0].replace('extern "C" int __wrap_ioctl(', 'extern "C" int priorIoctl(',1)
code+=r'''
#include <linux/netfilter/gta3xlwifi_packet_stats.h>
using PS=NetpolicyLease::PacketState;using PP=NetpolicyLease::PacketSnapshot;using AP=NetpolicyLease::AppSnapshot;using BT=NetpolicyLease::BankTransition;
static unsigned calls,retries,fault,error;static bool appRead;static int errorCode;
static gta3xlwifi_packet_stats_state st;
static std::vector<gta3xlwifi_packet_stats_entry> packets;
static std::vector<gta3xlwifi_app_stats_entry> apps;
static uint64_t loss,sequence;
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
 va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);
 if(cmd!=GTA3XLWIFI_STATS_GET_STATE&&cmd!=GTA3XLWIFI_STATS_READ&&cmd!=GTA3XLWIFI_STATS_SWAP&&cmd!=GTA3XLWIFI_STATS_ACK&&cmd!=GTA3XLWIFI_STATS_EDIT)return priorIoctl(fd,cmd,arg);
 assert(files.count(fd)&&arg);++calls;
 if(cmd==GTA3XLWIFI_STATS_GET_STATE){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_state*>(arg);gta3xlwifi_packet_stats_state zero{};assert(!memcmp(x,&zero,sizeof(zero)));*x=st;switch(fault){case 0:break;case 1:x->version=2;break;case 2:x->reserved=1;break;case 3:x->active_bank=2;break;case 4:x->active_epoch=0;break;case 5:x->pending_mask=4;break;case 6:x->pending_mask=1;break;case 7:x->bank_epoch[0]=9;break;case 8:x->app_count=10001;break;case 9:x->counterset_count=20001;break;case 10:x->bank_count[0]=5001;break;case 11:x->bank_epoch[1]=99;break;case 12:x->pending_mask=2;x->bank_epoch[1]=0;break;default:assert(false);}}
 else if(cmd==GTA3XLWIFI_STATS_READ){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_transfer*>(arg);assert(x->version==1&&!x->reserved&&!x->lost_updates&&!x->sequence&&x->entries);void*rows=reinterpret_cast<void*>(uintptr_t(x->entries));
  if(appRead){assert(x->kind==2&&!x->epoch&&x->count==10000);std::copy(apps.begin(),apps.end(),static_cast<gta3xlwifi_app_stats_entry*>(rows));x->count=apps.size();}
  else{assert(x->kind==1&&x->epoch==7&&x->count==5000);std::copy(packets.begin(),packets.end(),static_cast<gta3xlwifi_packet_stats_entry*>(rows));x->count=packets.size();}
  x->lost_updates=loss;x->sequence=sequence;
  switch(fault){case 0:break;case 1:x->version=2;break;case 2:x->kind=3;break;case 3:++x->epoch;break;case 4:x->reserved=1;break;case 5:x->count=10001;break;case 6:x->entries=1;break;
   case 7:if(appRead)static_cast<gta3xlwifi_app_stats_entry*>(rows)[0].reserved=1;else static_cast<gta3xlwifi_packet_stats_entry*>(rows)[0].key.counterset=2;break;
   case 8:if(appRead)static_cast<gta3xlwifi_app_stats_entry*>(rows)[1].uid=apps[0].uid;else static_cast<gta3xlwifi_packet_stats_entry*>(rows)[1].key=packets[0].key;break;
   case 9:if(appRead)std::swap(static_cast<gta3xlwifi_app_stats_entry*>(rows)[0],static_cast<gta3xlwifi_app_stats_entry*>(rows)[1]);else std::swap(static_cast<gta3xlwifi_packet_stats_entry*>(rows)[0],static_cast<gta3xlwifi_packet_stats_entry*>(rows)[1]);break;default:assert(false);}
 }else if(cmd==GTA3XLWIFI_STATS_SWAP){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_swap*>(arg);assert(x->version==1&&x->active_bank==0&&x->active_epoch==1&&!x->inactive_bank&&!x->reserved&&!x->inactive_epoch);x->active_bank=1;x->active_epoch=2;x->inactive_bank=0;x->inactive_epoch=1;st.active_bank=1;st.active_epoch=2;st.bank_epoch[1]=2;st.pending_mask=1;switch(fault){case 0:break;case 1:x->version=2;break;case 2:x->reserved=1;break;case 3:x->active_bank=0;break;case 4:x->active_epoch=3;break;case 5:x->inactive_bank=1;break;case 6:x->inactive_epoch=9;break;default:assert(false);}}
 else if(cmd==GTA3XLWIFI_STATS_ACK){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_ack*>(arg);assert(x->version==1&&x->bank==1&&x->epoch==7&&!x->reserved);}
 else{auto*x=reinterpret_cast<gta3xlwifi_packet_stats_edit*>(arg);assert(x->version==1&&x->uid==123&&!x->tag&&!x->reserved);assert((x->operation==1&&x->counterset<=1)||(x->operation==2&&!x->counterset));}
 if(retries){--retries;errno=EINTR;return -1;}if(error){errno=errorCode;return error==2?1:-1;}return 0;
}
static void resetPacket(){resetEvents();features=4096;calls=retries=fault=error=0;errorCode=0;appRead=false;st={};st.version=1;st.active_epoch=1;st.bank_epoch[0]=1;packets={{{1,0,0,2},3,4,5,6},{{1,7,1,4},8,9,10,11}};apps={{1,0,3,4,5,6},{2,0,7,8,9,10}};loss=3;sequence=4;}
int main(){
 resetPacket();{NetpolicyLease l;PS s;PP p;AP a;BT b;C(l.readPacketState(nullptr)==-EINVAL);C(l.readFrozenPacketStats(2,7,&p)==-EINVAL);C(l.readFrozenPacketStats(1,0,&p)==-EINVAL);C(l.readAppStats(nullptr)==-EINVAL);C(l.swapPacketStats(0,UINT64_MAX,&b)==-EINVAL);C(l.acknowledgePacketStats(2,7)==-EINVAL);C(l.setPacketCounterset(123,2)==-EINVAL);C(l.readPacketState(&s)==-ENOTCONN&&!calls);C(l.start()==0);C(l.readPacketState(&s)==0&&s.activeEpoch==1&&held);retries=3;C(l.readPacketState(&s)==0&&!retries&&calls==5);C(l.readFrozenPacketStats(1,7,&p)==0&&p.entries.size()==2&&p.entries[1].tag==7&&p.lostUpdates==3&&p.sequence==4&&p.epoch==7);retries=2;C(l.readFrozenPacketStats(1,7,&p)==0&&!retries);appRead=true;retries=2;C(l.readAppStats(&a)==0&&a.entries.size()==2&&a.entries[1].txBytes==10&&a.lostUpdates==3&&!retries);C(l.swapPacketStats(0,1,&b)==0&&b.activeBank==1&&b.activeEpoch==2&&b.inactiveEpoch==1);retries=2;C(l.acknowledgePacketStats(1,7)==0&&!retries);C(l.setPacketCounterset(123,0)==0&&l.setPacketCounterset(123,1)==0&&l.deleteUidPacketStats(123)==0);C(l.release()==0&&!held);C(l.readAppStats(&a)==0&&!held&&opens==1);}
 for(unsigned f=1;f<=12;f++){resetPacket();fault=f;NetpolicyLease l;PS s;s.activeEpoch=99;C(l.start()==0&&l.readPacketState(&s)==-EPROTO&&s.activeEpoch==99&&files.empty()&&held);}
 for(bool app:{false,true})for(unsigned f=1;f<=9;f++){resetPacket();fault=f;appRead=app;NetpolicyLease l;PP p;p.epoch=99;AP a;a.sequence=99;C(l.start()==0);int r=app?l.readAppStats(&a):l.readFrozenPacketStats(1,7,&p);C(r==-EPROTO&&p.epoch==99&&a.sequence==99&&files.empty()&&held);}
 for(unsigned f=1;f<=6;f++){resetPacket();fault=f;NetpolicyLease l;BT b;b.activeEpoch=99;C(l.start()==0&&l.swapPacketStats(0,1,&b)==-EPROTO&&b.activeEpoch==99&&calls==1&&files.empty()&&held);}
 for(unsigned op=0;op<3;op++){resetPacket();retries=1;NetpolicyLease l;BT b;b.activeEpoch=99;C(l.start()==0);int r=op==0?l.swapPacketStats(0,1,&b):op==1?l.setPacketCounterset(123,1):l.deleteUidPacketStats(123);C(r==-EINTR&&calls==1&&files.empty()&&held&&b.activeEpoch==99);if(!op){C(st.active_bank==1&&st.pending_mask==1);C(l.start()==0);PS state;C(l.readPacketState(&state)==0&&state.activeBank==1&&state.pendingMask==1);}}
 for(int e:{EFAULT,EBUSY,ESTALE,ENODATA,EIO,ENOMEM,ENOTTY,0}){resetPacket();error=1;errorCode=e;NetpolicyLease l;PP p;p.epoch=99;C(l.start()==0&&l.readFrozenPacketStats(1,7,&p)==-(e?e:EIO)&&p.epoch==99&&files.empty()&&held);}
 resetPacket();error=2;{NetpolicyLease l;PS s;C(l.start()==0&&l.readPacketState(&s)==-EPROTO&&files.empty()&&held);}
 for(unsigned missing:{0,4095,8192}){resetPacket();features=missing;NetpolicyLease l;PS s;C(l.start()==0&&l.readPacketState(&s)==-EOPNOTSUPP&&files.empty()&&!calls&&held);}
 resetPacket();packets.clear();apps.clear();{NetpolicyLease l;PP p;AP a;C(l.start()==0&&l.readFrozenPacketStats(1,7,&p)==0&&p.entries.empty());appRead=true;C(l.readAppStats(&a)==0&&a.entries.empty());}
 resetPacket();for(unsigned i=2;i<5000;i++)packets.push_back({{i,0,i&1,UINT32_MAX},UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX});for(unsigned i=2;i<10000;i++)apps.push_back({i+1,0,UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX});loss=sequence=UINT64_MAX;{NetpolicyLease l;PP p;AP a;C(l.start()==0&&l.readFrozenPacketStats(1,7,&p)==0&&p.entries.size()==5000&&p.entries.back().txBytes==UINT64_MAX&&p.lostUpdates==UINT64_MAX);appRead=true;C(l.readAppStats(&a)==0&&a.entries.size()==10000&&a.sequence==UINT64_MAX);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(S/'Gta3xlwifiNetpolicyLease.cpp'),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+n for n in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=80
paths=[Path(__file__),R/'report.json',R/'test.cpp',S/'Gta3xlwifiNetpolicyLease.cpp',S/'Gta3xlwifiNetpolicyLease.h',*[p for p in (S/'linux/netfilter').glob('*.h')],O/'test.cpp'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
