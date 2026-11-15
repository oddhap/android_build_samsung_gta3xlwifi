#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual name-reader/owner/service with explicit ioctl/Binder/kernel fixtures.

Replays26184 prior owner/service checks, updating only the newly valid kind4
negative boundary to kind5. Separate real kernel/CFI/SDK builds are required.
"""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==26184
for name,h in r['inputs_sha256'].items():assert sha(Path(name))==h
for n in ['binder','com']:shutil.copytree(R/n,O/n)
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
code=(R/'test.cpp').read_text().replace('int main(){','static int previous_name_regressions(){',1).replace('extern "C" int __wrap_ioctl(', 'extern "C" int nameBaseIoctl(',1)
assert code.count('for(int kind:{-1,4})')==1;code=code.replace('for(int kind:{-1,4})','for(int kind:{-1,5})')
code+=r'''
#include <fstream>
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
static std::vector<gta3xlwifi_iface_name_entry>nameRows;
static uint64_t nameLoss,nameSequence;static unsigned nameCalls,nameFault,nameRetries;static int nameError,namePositive;
static gta3xlwifi_iface_name_entry named(uint32_t index,const char*text){gta3xlwifi_iface_name_entry r{};r.ifindex=index;assert(strlen(text)<16);memcpy(r.name,text,strlen(text));return r;}
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);if(cmd!=GTA3XLWIFI_IFACE_NAMES_GET)return nameBaseIoctl(fd,cmd,arg);
 assert(files.count(fd)&&arg);++nameCalls;auto*t=reinterpret_cast<gta3xlwifi_iface_names_transfer*>(arg);assert(t->version==1&&t->count==1000&&t->entries&&!t->lost_updates&&!t->update_sequence);auto*rows=reinterpret_cast<gta3xlwifi_iface_name_entry*>(uintptr_t(t->entries));assert(nameRows.size()<=1000);std::copy(nameRows.begin(),nameRows.end(),rows);t->count=nameRows.size();t->lost_updates=nameLoss;t->update_sequence=nameSequence;
 switch(nameFault){case 0:break;case 1:t->version=2;break;case 2:t->count=1001;break;case 3:t->entries+=8;break;case 4:rows[0].ifindex=0;break;case 5:rows[0].ifindex=uint32_t(INT_MAX)+1;break;case 6:rows[1].ifindex=rows[0].ifindex;break;case 7:std::swap(rows[0],rows[1]);break;case 8:memset(rows[0].name,0,16);break;case 9:memset(rows[0].name,'x',16);break;case 10:rows[0].name[15]='x';break;case 11:rows[0].name[0]='/';break;case 12:rows[0].name[0]=' ';break;case 13:rows[0].name[0]=char(128);break;case 14:memset(rows[0].name,0,16);rows[0].name[0]='.';break;default:assert(false);}
 if(nameRetries){--nameRetries;errno=EINTR;return -1;}if(nameError){errno=nameError;return -1;}return namePositive;
}
static void resetNames(){resetActive();features=131071;nameLoss=0;nameSequence=UINT64_MAX;nameCalls=nameFault=nameRetries=0;nameError=namePositive=0;nameRows={named(1,"lo"),named(7,"wlan0"),named(500,"0123456789abcde")};}
int main(int argc,char**argv){assert(argc==2);C(!previous_name_regressions());unsigned begin=cases;android::IPCThreadState::uid=1000;
 resetNames();{NetpolicyLease lease;NetpolicyLease::IfaceNamesSnapshot out;out.sequence=77;C(lease.readIfaceNames(nullptr)==-EINVAL);C(lease.readIfaceNames(&out)==-ENOTCONN&&out.sequence==77&&!nameCalls);}
 resetNames();{AccountingCombined kernel;P owner(kernel);NetpolicyLease::IfaceNamesSnapshot out;out.sequence=77;C(owner.readIfaceNames(&out)==-EAGAIN&&out.sequence==77);C(!owner.startWithAccounting(accountingProgram));C(owner.readIfaceNames(&out)==-EAGAIN&&!nameCalls);auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=0,generation=0;C(service->openSession(client,1,&session).isOk());std::vector<int64_t>words{77};
 for(uint32_t uid:{0u,1001u,1051u,1073u,10000u,101000u,UINT32_MAX}){android::IPCThreadState::uid=uid;C(service->readStats(session,4,0,0,&words).exception==-1&&words==std::vector<int64_t>{77}&&!nameCalls);}android::IPCThreadState::uid=1000;C(service->readStats(session+1,4,0,0,&words).code==ESTALE&&!nameCalls);C(service->readStats(session,4,1,0,&words).code==EINVAL&&!nameCalls);C(service->readStats(session,4,0,1,&words).code==EINVAL&&!nameCalls);C(service->readStats(session,4,0,0,&words).code==EAGAIN&&!nameCalls);
 send(*service,session,0,image());C(service->commitFrame(session,&generation).isOk());C(service->readStats(session,4,0,0,&words).isOk());C(words.size()==20&&words[0]==1&&words[1]==4&&words[2]==-1&&words[3]==0&&words[4]==3&&words[5]==1&&words[6]==0x6c6f0000L&&words[10]==7&&words[11]==0x776c616eL&&words[12]==0x30000000L);std::ofstream file(argv[1]);for(size_t i=0;i<words.size();++i)file<<(i?",":"")<<words[i];file<<"\n";file.close();C(file.good());C(!owner.readIfaceNames(&out)&&out.entries.size()==3&&out.sequence==UINT64_MAX&&out.lostUpdates==0&&!strcmp(out.entries[1].name.data(),"wlan0"));C(!held&&files.size()==1);nameLoss=UINT64_MAX;C(!owner.readIfaceNames(&out)&&out.lostUpdates==UINT64_MAX);nameRows.clear();C(!owner.readIfaceNames(&out)&&out.entries.empty());nameRows.reserve(1000);for(unsigned i=1;i<=1000;++i)nameRows.push_back(named(i,"iface"));C(!owner.readIfaceNames(&out)&&out.entries.size()==1000&&out.entries.back().ifindex==1000);C(service->closeSession(client).isOk()&&held);}
 for(unsigned fault=1;fault<=14;++fault){resetNames();AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram)&&!owner.replace(desired(),0));nameFault=fault;NetpolicyLease::IfaceNamesSnapshot out;out.sequence=77;out.entries.push_back({99,{}});C(owner.readIfaceNames(&out)==-EPROTO&&held&&files.empty());C(out.sequence==77&&out.entries.size()==1&&out.entries[0].ifindex==99);uint64_t g=88;C(owner.frameworkGeneration(&g)==-ENOTCONN&&g==88);}
 resetNames();{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram)&&!owner.replace(desired(),0));features=65535;NetpolicyLease::IfaceNamesSnapshot out;C(owner.readIfaceNames(&out)==-EOPNOTSUPP&&!nameCalls&&held&&files.empty());}
 for(int error:{EIO,EACCES,ENOTTY}){resetNames();AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram)&&!owner.replace(desired(),0));nameError=error;NetpolicyLease::IfaceNamesSnapshot out;C(owner.readIfaceNames(&out)==-error&&held&&files.empty()&&nameCalls==1);}
 resetNames();{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram)&&!owner.replace(desired(),0));namePositive=1;NetpolicyLease::IfaceNamesSnapshot out;C(owner.readIfaceNames(&out)==-EPROTO&&held&&files.empty());}
 resetNames();{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram)&&!owner.replace(desired(),0));nameRetries=3;NetpolicyLease::IfaceNamesSnapshot out;C(!owner.readIfaceNames(&out)&&nameCalls==4&&out.entries.size()==3&&!held);}
 C(files.empty()&&held);printf("iface_name_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);old=next(Path(v).parent for v in r['command'] if v.endswith('/Gta3xlwifiSocketPolicyProjection.cpp'));cmd=[v.replace(str(R),str(O)).replace(str(old),str(S)) for v in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test'),str(O/'names-wire.txt')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'iface_name_cases=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
paths=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',O/'names-wire.txt',*[q for q in S.rglob('*') if q.is_file()]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[2]),'new_interface_name_cases':int(m[1]),'prior_kind4_invalid_boundary_updated_to_kind5':True,'old_kernel_missing_capability_fails_held':True,'malformed_error_positive_and_loss_cases':True,'actual_service_serialized_names_for_Java':str(O/'names-wire.txt'),'inputs_sha256':{str(q):sha(q) for q in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
