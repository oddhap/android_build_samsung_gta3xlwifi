#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual shared-owner statistics facade, publication gates and whole-state failure withdrawal.

Replays the bound accounting-owner regression before exercising real transport
and facade with wire/syscall fixtures. No RPC, poll persistence, rules or Ready.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==1251 and r['start_fault_points']==74;assert sha(R/'test.cpp')==r['inputs_sha256'][str(R/'test.cpp')]
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h');code=(R/'test.cpp').read_text().replace('extern "C" int __wrap_ioctl(', 'extern "C" int ownerBaseIoctl(',1).replace('int main(){','static int accounting_regression_main(){',1)
needle='printf("passed_cases=%u start_fault_points=%u replace_fault_points=%u\\n",cases,startPoints,replacePoints);';assert needle in code;code=code.replace(needle,needle+'return 0;',1)
code+=r'''
#include <linux/netfilter/gta3xlwifi_packet_stats.h>
static unsigned packetCalls,packetRetries,packetError;static int packetErrno;static bool packetBad,appRead;
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
 va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);
 if(cmd!=GTA3XLWIFI_STATS_GET_STATE&&cmd!=GTA3XLWIFI_STATS_READ&&cmd!=GTA3XLWIFI_STATS_SWAP&&cmd!=GTA3XLWIFI_STATS_ACK&&cmd!=GTA3XLWIFI_STATS_EDIT)return ownerBaseIoctl(fd,cmd,arg);
 assert(files.count(fd)&&arg);++packetCalls;
 if(cmd==GTA3XLWIFI_STATS_GET_STATE){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_state*>(arg);gta3xlwifi_packet_stats_state zero{};assert(!memcmp(x,&zero,sizeof(zero)));x->version=1;x->active_epoch=1;x->bank_epoch[0]=1;x->total_stats_lost=UINT64_MAX;if(packetBad)x->version=2;}
 else if(cmd==GTA3XLWIFI_STATS_READ){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_transfer*>(arg);assert(x->version==1&&!x->reserved&&!x->lost_updates&&!x->sequence&&x->entries);
  if(appRead){assert(x->kind==2&&x->epoch==0&&x->count==10000);auto*rows=reinterpret_cast<gta3xlwifi_app_stats_entry*>(uintptr_t(x->entries));rows[0]={1,0,3,4,5,6};}
  else{assert(x->kind==1&&x->epoch==7&&x->count==5000);auto*rows=reinterpret_cast<gta3xlwifi_packet_stats_entry*>(uintptr_t(x->entries));rows[0]={{1,7,1,17},3,4,5,6};}
  x->count=1;x->lost_updates=UINT64_MAX;x->sequence=UINT64_MAX;if(packetBad)x->version=2;
 }else if(cmd==GTA3XLWIFI_STATS_SWAP){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_swap*>(arg);assert(x->version==1&&x->active_bank==0&&x->active_epoch==1&&!x->inactive_bank&&!x->reserved&&!x->inactive_epoch);x->active_bank=1;x->active_epoch=2;x->inactive_bank=0;x->inactive_epoch=1;if(packetBad)x->version=2;}
 else if(cmd==GTA3XLWIFI_STATS_ACK){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_ack*>(arg);assert(x->version==1&&x->bank==1&&x->epoch==7&&!x->reserved);}
 else{auto*x=reinterpret_cast<gta3xlwifi_packet_stats_edit*>(arg);assert(x->version==1&&x->uid==123&&!x->tag&&!x->reserved&&((x->operation==1&&x->counterset<=1)||(x->operation==2&&!x->counterset)));}
 if(packetRetries){--packetRetries;errno=EINTR;return -1;}if(packetError){errno=packetErrno;return packetError==2?1:-1;}return 0;
}
static void resetApi(){resetIntegrated();packetCalls=packetRetries=packetError=0;packetErrno=0;packetBad=appRead=false;}
struct Outputs{NetpolicyLease::PacketState state;NetpolicyLease::PacketSnapshot packet;NetpolicyLease::AppSnapshot app;NetpolicyLease::BankTransition transition;Outputs(){state.activeEpoch=99;packet.epoch=99;app.sequence=99;transition.activeEpoch=99;}bool unchanged()const{return state.activeEpoch==99&&packet.epoch==99&&app.sequence==99&&transition.activeEpoch==99;}};
static int operation(P&p,unsigned op,Outputs&o){appRead=op==2;switch(op){case 0:return p.readPacketState(&o.state);case 1:return p.readFrozenPacketStats(1,7,&o.packet);case 2:return p.readAppStats(&o.app);case 3:return p.swapPacketStats(0,1,&o.transition);case 4:return p.acknowledgePacketStats(1,7);case 5:return p.setPacketCounterset(123,1);case 6:return p.deleteUidPacketStats(123);default:assert(false);}}
int main(){
 assert(accounting_regression_main()==0);unsigned before=cases;
 resetApi();{AccountingCombined k;P p(k);Outputs o;for(unsigned op=0;op<7;op++)C(operation(p,op,o)==-EAGAIN&&packetCalls==0&&o.unchanged());C(p.startWithAccounting(accountingProgram)==0);for(unsigned op=0;op<7;op++)C(operation(p,op,o)==-EAGAIN&&packetCalls==0&&o.unchanged()&&held);C(p.replace(desired(),0)==0&&!held&&opens==1);for(unsigned op=0;op<7;op++)C(operation(p,op,o)==0&&!held&&opens==1&&files.size()==1);C(o.state.activeEpoch==1&&o.state.totalStatsLost==UINT64_MAX);C(o.packet.entries.size()==1&&o.packet.epoch==7&&o.packet.entries[0].uid==1&&o.packet.entries[0].tag==7&&o.packet.entries[0].counterset==1&&o.packet.entries[0].ifindex==17&&o.packet.entries[0].txBytes==6&&o.packet.lostUpdates==UINT64_MAX);C(o.app.entries.size()==1&&o.app.entries[0].uid==1&&o.app.entries[0].txBytes==6&&o.app.sequence==UINT64_MAX);C(o.transition.activeBank==1&&o.transition.activeEpoch==2&&o.transition.inactiveEpoch==1);C(p.setPacketCounterset(123,0)==0);auto calls=packetCalls;C(p.readPacketState(nullptr)==-EINVAL);C(p.readFrozenPacketStats(2,7,&o.packet)==-EINVAL);C(p.readFrozenPacketStats(1,0,&o.packet)==-EINVAL);C(p.readAppStats(nullptr)==-EINVAL);C(p.swapPacketStats(0,UINT64_MAX,&o.transition)==-EINVAL);C(p.acknowledgePacketStats(2,7)==-EINVAL);C(p.setPacketCounterset(-1,1)==-EINVAL);C(p.setPacketCounterset(123,2)==-EINVAL);C(p.deleteUidPacketStats(-1)==-EINVAL&&packetCalls==calls&&!held);p.stop();for(unsigned op=0;op<7;op++)C(operation(p,op,o)==-EAGAIN&&packetCalls==calls&&held);}
 resetApi();{AccountingCombined k;P p(k);Outputs o;C(p.start()==0&&p.replace(desired(),0)==0&&!held);for(unsigned op=0;op<7;op++)C(operation(p,op,o)==-EOPNOTSUPP&&packetCalls==0&&o.unchanged()&&!held);P::State state;uint64_t g=0;C(p.snapshot(&state,&g)==0&&g==1);}
 for(unsigned op=0;op<7;op++)for(int error:{EIO,EFAULT,ENOMEM,ESTALE,ENOSPC,0}){resetApi();AccountingCombined k;P p(k);Outputs o;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);packetError=error?1:2;packetErrno=error;C(operation(p,op,o)==-(error?error:EPROTO)&&o.unchanged()&&files.empty()&&held&&packetCalls==1);P::State state;uint64_t g=77;C(p.snapshot(&state,&g)==-EAGAIN&&g==77);C(p.setDataSaver(false)==-EAGAIN);auto calls=packetCalls;C(operation(p,op,o)==-EAGAIN&&packetCalls==calls);}
 for(unsigned op=0;op<4;op++){resetApi();AccountingCombined k;P p(k);Outputs o;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);packetBad=true;C(operation(p,op,o)==-EPROTO&&o.unchanged()&&held&&files.empty());}
 for(unsigned op:{0u,1u,2u,4u}){resetApi();AccountingCombined k;P p(k);Outputs o;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);packetRetries=3;C(operation(p,op,o)==0&&!packetRetries&&packetCalls==4&&!held&&opens==1);}
 for(unsigned op:{3u,5u,6u}){resetApi();AccountingCombined k;P p(k);Outputs o;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);packetRetries=1;C(operation(p,op,o)==-EINTR&&o.unchanged()&&packetCalls==1&&files.empty()&&held);}
 C(files.empty()&&held);printf("owner_api_cases=%u total_cases=%u\n",cases-before,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);names=['Gta3xlwifiNetpolicyLease','Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiSocketRoots','Gta3xlwifiIngressPolicy','Gta3xlwifiMeteredChainProgram','Gta3xlwifiMeteredRoots','Gta3xlwifiUidPermissionState','Gta3xlwifiLocalNetworkState','Gta3xlwifiSocketPolicyProjection','Gta3xlwifiAccountingRoots'];sources=[S/(n+'.cpp') for n in names];cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+n for n in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=120,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);match=re.fullmatch(r'passed_cases=1251 start_fault_points=74 replace_fault_points=114\nowner_api_cases=(\d+) total_cases=(\d+)\n',x.stdout);assert match and int(match[1])>=100
paths=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',O/'IptablesRestoreController.h',S/'projection-guards.inc',*sources,*[p.with_suffix('.h') for p in sources],*[p for p in (S/'linux/netfilter').glob('*.h')]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[2]),'owner_api_cases':int(match[1]),'start_fault_points':74,'replace_fault_points':114,'one_lease_four_state_publication':True,'hard_no_firewall_after_first_image_set':True,'actual_accounting_startup_and_reverification':True,'packet_storage_and_compiled_hooks_required_before_firewall':True,'primitive_controls_withdraw_complete_publication_on_error':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
