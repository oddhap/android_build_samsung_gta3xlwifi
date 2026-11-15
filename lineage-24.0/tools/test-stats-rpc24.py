#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual statistics Binder service/owner with explicit Binder/ioctl/rule fixtures."""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==26050 and sha(R/'test.cpp')==r['inputs_sha256'][str(R/'test.cpp')]
for n in ['binder','com']:shutil.copytree(R/n,O/n)
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
h=O/'com/android/internal/net/BnGta3xlwifiNetpolicy.h';t=h.read_text().replace('};}', '''virtual ::android::binder::Status readStats(int64_t,int32_t,int32_t,int64_t,std::vector<int64_t>*)=0;
 virtual ::android::binder::Status swapStats(int64_t,int32_t,int64_t,std::vector<int64_t>*)=0;
 virtual ::android::binder::Status acknowledgeStats(int64_t,int32_t,int64_t)=0;
 virtual ::android::binder::Status setStatsCounterset(int64_t,int32_t,int32_t)=0;
};}''');h.write_text(t)
code=(R/'test.cpp').read_text().replace('int main(){','static int previous_stats_regressions(){',1).replace('extern "C" int __wrap_ioctl(', 'extern "C" int statsBaseIoctl(',1)
code=code.replace('static unsigned packetCalls,','static unsigned largeStatsRows;static unsigned packetCalls,',1)
needle='x->count=1;x->lost_updates=UINT64_MAX;x->sequence=UINT64_MAX;if(packetBad)'
assert code.count(needle)==1
code=code.replace(needle,'''if(largeStatsRows){for(unsigned i=0;i<largeStatsRows;++i){
 if(appRead){auto*r=reinterpret_cast<gta3xlwifi_app_stats_entry*>(uintptr_t(x->entries));r[i]={i+1,0,3,4,5,6};}
 else{auto*r=reinterpret_cast<gta3xlwifi_packet_stats_entry*>(uintptr_t(x->entries));r[i]={{i+1,7,1,17},3,4,5,6};}
 }}x->count=largeStatsRows?largeStatsRows:1;x->lost_updates=UINT64_MAX;x->sequence=UINT64_MAX;if(packetBad)''',1)
code+=r'''
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
extern "C" int __wrap_ioctl(int fd,unsigned long command,...){va_list v;va_start(v,command);unsigned long arg=va_arg(v,unsigned long);va_end(v);
 if(command!=GTA3XLWIFI_IFACE_STATS_GET)return statsBaseIoctl(fd,command,arg);
 assert(files.count(fd)&&arg);auto*x=reinterpret_cast<gta3xlwifi_iface_stats_transfer*>(arg);
 assert(x->version==1&&x->count==1000&&x->entries&&!x->lost_updates&&!x->update_sequence);
 auto*rows=reinterpret_cast<gta3xlwifi_iface_stats_entry*>(uintptr_t(x->entries));rows[0]={17,0,UINT64_MAX,1,2,3};x->count=1;x->lost_updates=UINT64_MAX;x->update_sequence=UINT64_MAX;return 0;
}
int main(){C(!previous_stats_regressions());unsigned begin=cases;
 resetActive();{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=0,g=0;android::IPCThreadState::uid=1000;C(service->openSession(client,1,&session).isOk());std::vector<int64_t>out{777};
 for(uint32_t uid:{0u,1001u,1051u,1073u,10000u,101000u,UINT32_MAX}){android::IPCThreadState::uid=uid;auto n=ioCount;C(service->readStats(session,0,0,0,&out).exception==-1);C(service->swapStats(session,0,1,&out).exception==-1);C(service->acknowledgeStats(session,1,7).exception==-1);C(service->setStatsCounterset(session,123,1).exception==-1);C(out==std::vector<int64_t>{777}&&ioCount==n);}
 android::IPCThreadState::uid=1000;
 C(service->readStats(session+1,0,0,0,&out).code==ESTALE);C(service->swapStats(session+1,0,1,&out).code==ESTALE);C(service->acknowledgeStats(session+1,1,7).code==ESTALE);C(service->setStatsCounterset(session+1,123,1).code==ESTALE);
 C(service->readStats(session,0,0,0,&out).code==EAGAIN&&out==std::vector<int64_t>{777});C(service->swapStats(session,0,1,&out).code==EAGAIN);C(service->acknowledgeStats(session,1,7).code==EAGAIN);C(service->setStatsCounterset(session,123,1).code==EAGAIN);
 for(int kind:{-1,4})C(service->readStats(session,kind,0,0,&out).code==EINVAL);
 for(int bank:{-1,2}){C(service->readStats(session,1,bank,7,&out).code==EINVAL);C(service->swapStats(session,bank,1,&out).code==EINVAL);C(service->acknowledgeStats(session,bank,7).code==EINVAL);}
 C(service->readStats(session,1,1,0,&out).code==EINVAL);C(service->readStats(session,0,1,0,&out).code==EINVAL);C(service->readStats(session,2,0,7,&out).code==EINVAL);C(service->readStats(session,3,0,0,nullptr).code==EINVAL);C(service->swapStats(session,0,0,&out).code==EINVAL);C(service->swapStats(session,0,1,nullptr).code==EINVAL);C(service->acknowledgeStats(session,0,0).code==EINVAL);C(service->setStatsCounterset(session,-1,0).code==EINVAL);C(service->setStatsCounterset(session,123,-1).code==EINVAL);C(service->setStatsCounterset(session,123,2).code==EINVAL);
 send(*service,session,0,image());C(service->commitFrame(session,&g).isOk()&&g>0&&!held);
 C(service->readStats(session,0,0,0,&out).isOk());C(out.size()==15&&out[0]==1&&out[1]==0&&out[2]==0&&out[3]==1&&out.back()==-1);
 appRead=false;C(service->readStats(session,1,1,7,&out).isOk());C(out==std::vector<int64_t>({1,1,1,7,-1,-1,1,1,7,1,17,3,4,5,6}));
 appRead=true;C(service->readStats(session,2,0,0,&out).isOk());C(out==std::vector<int64_t>({1,2,-1,-1,1,1,3,4,5,6}));
 C(service->readStats(session,3,0,0,&out).isOk());C(out==std::vector<int64_t>({1,3,-1,-1,1,17,-1,1,2,3}));
 largeStatsRows=5000;appRead=false;C(service->readStats(session,1,1,7,&out).isOk());C(out.size()==40007&&out[6]==5000&&out[7+8*4999]==5000&&out.back()==6);
 largeStatsRows=10000;appRead=true;C(service->readStats(session,2,0,0,&out).isOk());C(out.size()==50005&&out[4]==10000&&out[5+5*9999]==10000&&out.back()==6);
 largeStatsRows=0;
 C(service->swapStats(session,0,1,&out).isOk());C(out==std::vector<int64_t>({1,2,0,1}));C(service->acknowledgeStats(session,1,7).isOk());C(service->setStatsCounterset(session,123,1).isOk());C(service->setStatsCounterset(session,123,0).isOk());
 C(service->closeSession(client).isOk()&&held);C(service->readStats(session,0,0,0,&out).code==ESTALE);
 }
 for(unsigned op=0;op<4;++op){resetActive();AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=0,g=0;C(service->openSession(client,1,&session).isOk());send(*service,session,0,image());C(service->commitFrame(session,&g).isOk());std::vector<int64_t>out{777};packetError=1;packetErrno=EIO;auto before=packetCalls;
 android::binder::Status r;switch(op){case 0:r=service->readStats(session,0,0,0,&out);break;case 1:r=service->swapStats(session,0,1,&out);break;case 2:r=service->acknowledgeStats(session,1,7);break;default:r=service->setStatsCounterset(session,123,1);}
 C(r.code==EIO&&held&&files.empty());C(out==std::vector<int64_t>{777}&&packetCalls==before+1);C(service->readStats(session,0,0,0,&out).code==EAGAIN);
 }
 C(files.empty()&&held);printf("stats_rpc_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);old=next(Path(v).parent for v in r['command'] if v.endswith('/Gta3xlwifiSocketPolicyProjection.cpp'));cmd=[v.replace(str(R),str(O)).replace(str(old),str(S)) for v in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'stats_rpc_cases=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
paths=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',h,*[Path(v) for v in cmd if v.startswith(str(S)) and v.endswith('.cpp')],*S.glob('Gta3xlwifi*.h')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[2]),'new_stats_RPC_cases':int(m[1]),'maximum_5000_packet_and_10000_app_rows_executed':True,'actual_unsigned64_bits_preserved':True,'all_RPC_full_UID_auth_and_session_checks':True,'failed_mutation_not_retried_and_owner_quarantines':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
