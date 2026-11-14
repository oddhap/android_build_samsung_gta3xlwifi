#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual frame/service/owner with Binder identity/death and syscall fixtures.

The Android-generated transport is compiled separately. Host Binder/kernel/table
fixtures here do not establish real IPC, packets or device networking readiness.
"""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();reference=json.loads((R/'report.json').read_text());assert reference['passed'] and reference['passed_cases']==23026
assert sha(R/'test.cpp')==reference['inputs_sha256'][str(R/'test.cpp')]
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
def header(path,text):
 p=O/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
header('binder/IBinder.h',r'''#pragma once
#include <memory>
#include <vector>
#include <cstdint>
namespace android {
inline constexpr int OK=0;
template<class T> class wp;
template<class T> class sp:public std::shared_ptr<T>{
 public:using std::shared_ptr<T>::shared_ptr;sp()=default;sp(const std::shared_ptr<T>&p):std::shared_ptr<T>(p){}
 template<class U>sp(const sp<U>&p):std::shared_ptr<T>(p){}
 template<class...A>static sp<T>make(A&&...a){return std::make_shared<T>(std::forward<A>(a)...);}
 void clear(){this->reset();}
};
template<class T>class wp:public std::weak_ptr<T>{
 public:using std::weak_ptr<T>::weak_ptr;wp()=default;wp(const sp<T>&p):std::weak_ptr<T>(p){}
 static wp<T>fromExisting(T*p){return sp<T>(std::static_pointer_cast<T>(p->shared_from_this()));}
 sp<T>promote()const{return this->lock();}
};
class IBinder:public std::enable_shared_from_this<IBinder>{
 public:class DeathRecipient{public:virtual ~DeathRecipient()=default;virtual void binderDied(const wp<IBinder>&)=0;};
 virtual ~IBinder()=default;int linkError=0;std::vector<sp<DeathRecipient>>deaths;
 int linkToDeath(const sp<DeathRecipient>&d){if(linkError)return linkError;deaths.push_back(d);return OK;}
 int unlinkToDeath(const sp<DeathRecipient>&d){for(auto i=deaths.begin();i!=deaths.end();++i)if(*i==d){deaths.erase(i);return OK;}return -1;}
 void kill(){auto current=deaths;deaths.clear();for(auto&d:current)d->binderDied(wp<IBinder>(sp<IBinder>(shared_from_this())));}
};
namespace binder{class Status{public:static constexpr int EX_SECURITY=-1;int code=0,exception=0;
 static Status ok(){return {};}
 static Status fromServiceSpecificError(int c){Status s;s.code=c;return s;}
 static Status fromExceptionCode(int c){Status s;s.exception=c;return s;}
 bool isOk()const{return !code&&!exception;}
};}
}
''')
header('binder/IPCThreadState.h',r'''#pragma once
#include <cstdint>
namespace android {class IPCThreadState{public:static inline thread_local uint32_t uid=1000;static IPCThreadState*self(){static thread_local IPCThreadState v;return &v;}uint32_t getCallingUid(){return uid;}};}
''')
header('com/android/internal/net/BnGta3xlwifiNetpolicy.h',r'''#pragma once
#include <binder/IBinder.h>
namespace com::android::internal::net {
class BnGta3xlwifiNetpolicy:public ::android::IBinder{
 public:
 virtual ::android::binder::Status openSession(const ::android::sp<::android::IBinder>&,int32_t,int64_t*)=0;
 virtual ::android::binder::Status beginFrame(int64_t,int64_t,const std::vector<int32_t>&,int32_t,bool,bool,bool)=0;
 virtual ::android::binder::Status appendFrame(int64_t,int32_t,int32_t,const std::vector<int32_t>&)=0;
 virtual ::android::binder::Status commitFrame(int64_t,int64_t*)=0;
 virtual ::android::binder::Status abandonFrame(int64_t)=0;
 virtual ::android::binder::Status readGeneration(int64_t,int64_t*)=0;
 virtual ::android::binder::Status closeSession(const ::android::sp<::android::IBinder>&)=0;
};}
''')
code=(R/'test.cpp').read_text().replace('int main(){','static int provider_regressions(){',1)
code+=r'''
#include "Gta3xlwifiPolicyFrame.h"
#include "Gta3xlwifiNetpolicyService.h"
#include <binder/IPCThreadState.h>
#include <random>
using Frame=android::net::gta3xlwifi::PolicyFrame;
using Service=android::net::gta3xlwifi::NetpolicyService;
using android::IBinder;using android::sp;
using Sections=std::array<std::vector<int32_t>,Frame::SectionCount>;
static Sections image(){Sections v;v[Frame::Users]={0};v[Frame::KnownUids]={10001,10002};v[Frame::RawPermissions]={0,1023,1000,1023,10001,4};for(const auto&c:android::net::gta3xlwifi::UidPolicy::chains()){v[Frame::ChainConfiguration].push_back(c.id);v[Frame::ChainConfiguration].push_back(0);}return v;}
static std::vector<int32_t>counts(const Sections&v){std::vector<int32_t>r;for(auto&s:v)r.push_back(s.size());return r;}
static void fill(Frame&f,const Sections&v,unsigned chunk=4096){for(unsigned i=0;i<v.size();++i)for(unsigned offset=0;offset<v[i].size();offset+=chunk){auto end=std::min(offset+chunk,(unsigned)v[i].size());C(f.append(i,offset,{v[i].begin()+offset,v[i].begin()+end})==0);}}
static int compile(const Sections&v,P::State*out){Frame f;int e=f.begin(counts(v),7,true,true,true);if(e)return e;fill(f,v);return f.compile(out);}
static void reject(const Sections&v,int e){P::State out;out.policy.setDataSaver(true);C(compile(v,&out)==e&&out.policy.dataSaver());}
static void send(Service&s,int64_t session,int64_t generation,const Sections&v,unsigned chunk=4096){C(s.beginFrame(session,generation,counts(v),7,true,true,true).isOk());for(unsigned i=0;i<v.size();++i)for(unsigned off=0;off<v[i].size();off+=chunk){auto end=std::min(off+chunk,(unsigned)v[i].size());C(s.appendFrame(session,i,off,{v[i].begin()+off,v[i].begin()+end}).isOk());}}
int main(){
 C(provider_regressions()==0);allowHeldActive=true;unsigned begin=cases;
 Frame frame;P::State output;C(frame.compile(&output)==-ENOTCONN);C(frame.append(0,0,{0})==-ENOTCONN);C(frame.begin(counts(image()),7,true,false,false)==-EOPNOTSUPP);C(frame.begin(counts(image()),8,true,true,false)==-EINVAL);
 C(frame.begin(counts(image()),7,true,true,false)==0);C(frame.begin(counts(image()),7,true,true,false)==-EBUSY);C(frame.compile(&output)==-EAGAIN);C(frame.append(100,0,{1})==-EINVAL);C(frame.append(0,1,{0})==-ESTALE);C(frame.append(0,0,{})==-EINVAL);C(frame.append(0,0,{0,1})==-E2BIG);C(frame.append(0,0,std::vector<int32_t>(4097))==-EINVAL);fill(frame,image(),1);C(frame.compile(&output)==0);uint32_t mask=99;C(!output.permissions.get(10001,&mask)&&mask==0);C(!output.permissions.get(10002,&mask)&&mask==4);C(!output.permissions.get(0,&mask)&&mask==123);C(output.runtime.supplied&&output.runtime.flags==7);C(frame.append(0,0,{0})==-ESTALE);frame.clear();C(frame.compile(&output)==-ENOTCONN);
 for(unsigned i=0;i<10;++i){auto n=counts(image());n[i]=-1;Frame f;C(f.begin(n,7,false,true,false)==-EINVAL);n[i]=INT32_MAX;C(f.begin(n,7,false,true,false)==-EINVAL);}
 {auto v=image();v[Frame::Users]={0,0};reject(v,-EINVAL);v=image();v[Frame::Users]={1};reject(v,-EPROTO);v=image();v[Frame::RawPermissions][1]=1022;reject(v,-EPROTO);v=image();v[Frame::RawPermissions][5]=1024;reject(v,-EINVAL);v=image();v[Frame::RawPermissions].insert(v[Frame::RawPermissions].end(),{10001,4});reject(v,-EINVAL);}
 {auto v=image();v[Frame::ChainConfiguration][2]=1;reject(v,-EINVAL);v=image();v[Frame::ChainConfiguration][1]=2;reject(v,-EINVAL);v=image();v[Frame::ChainMembership]={42,10001};reject(v,-EINVAL);v[Frame::ChainMembership]={1,-1};reject(v,-EINVAL);v[Frame::ChainMembership]={1,10001,1,10001};reject(v,-EINVAL);}
 {auto v=image();v[Frame::IngressOwners]={10001,0,1,0};reject(v,-EINVAL);v[Frame::IngressOwners]={10001,2,0,0};reject(v,-EINVAL);v[Frame::IngressOwners]={10001,1,-1,0};reject(v,-EINVAL);v[Frame::IngressOwners]={10001,1,0,0,10001,0,0,1};reject(v,-EINVAL);v[Frame::IngressOwners]={10001,1,0,1};C(!compile(v,&output));}
 {auto v=image();v[Frame::DiscardAddresses]={0,0,0,0,0,0};reject(v,-EINVAL);v[Frame::DiscardAddresses]={0,0,0,1,0,1,0,0,0,1,0,1};reject(v,-EINVAL);v[Frame::DiscardAddresses]={0,0,0,1,0,-1};reject(v,-EINVAL);v[Frame::DiscardAddresses]={0,0,0,1,0,1};C(!compile(v,&output));}
 for(auto section:{Frame::LocalNetworks,Frame::LocalHosts}){auto v=image();v[section]={193,0,0,0,0,0,0,0};reject(v,-EINVAL);v[section]={0,0,0,0,0,0,0,2};reject(v,-EINVAL);v[section]={0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,1};reject(v,-EEXIST);v[section]={192,0x01020304,0,0,0,0,0,0};C(!compile(v,&output));std::vector<android::net::gta3xlwifi::LocalNetworkState::Entry>network,host;C(!output.local.snapshot(&network,&host));const auto&e=section==Frame::LocalNetworks?network[0]:host[0];C(e.key[0]==1&&e.key[1]==2&&e.key[2]==3&&e.key[3]==4&&!e.allowed);}
 {auto v=image();v[Frame::LegacyBlockedUids]={10002,10001};reject(v,-EINVAL);v[Frame::LegacyBlockedUids]={10001,10001};reject(v,-EINVAL);v[Frame::LegacyBlockedUids]={-1};reject(v,-EINVAL);v[Frame::LegacyBlockedUids]={10001,10002};C(!compile(v,&output)&&output.runtime.legacyBlockedUids.size()==2);}
 // Full 65,536 known-UID boundary, observed INTERNET-only entries and zero-raw missing entries.
 {auto v=image();v[Frame::KnownUids]={0,1000};for(int i=10000;i<75534;++i)v[Frame::KnownUids].push_back(i);C(!compile(v,&output));C(!output.permissions.get(75533,&mask)&&mask==4);v[Frame::KnownUids].push_back(75536);reject(v,-EINVAL);}
 // Random chunk partitions must yield the same real state for all 128 canonical permissions.
 for(unsigned seed=1;seed<=128;++seed){auto v=image();v[Frame::RawPermissions][5]=(seed*7)&1023;Frame f;C(!f.begin(counts(v),seed&7,true,true,seed&1));fill(f,v,1+seed%17);C(!f.compile(&output));uint32_t canonical;C(!android::net::gta3xlwifi::PermissionBootstrap::convert((seed*7)&1023,true,&canonical));C(!output.permissions.get(10001,&mask)&&mask==canonical);}
 resetActive();{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=77,generation=77;
 for(uint32_t uid:{0u,1001u,1051u,1073u,10000u,101000u,UINT32_MAX}){android::IPCThreadState::uid=uid;C(service->openSession(client,1,&session).exception==-1&&session==77);C(service->beginFrame(1,0,counts(image()),7,true,true,true).exception==-1);C(service->appendFrame(1,0,0,{0}).exception==-1);C(service->commitFrame(1,&generation).exception==-1&&generation==77);C(service->abandonFrame(1).exception==-1);}
 android::IPCThreadState::uid=1000;C(service->openSession({},1,&session).code==EINVAL);C(service->openSession(client,2,&session).code==EINVAL);client->linkError=-1;C(service->openSession(client,1,&session).code==EPIPE);client->linkError=0;C(service->openSession(client,1,&session).isOk()&&session>0);int64_t again=0;C(service->openSession(client,1,&again).isOk()&&again==session);C(service->openSession(sp<IBinder>::make(),1,&again).code==EBUSY);C(service->commitFrame(session+1,&generation).code==ESTALE);C(service->commitFrame(session,&generation).code==ENOTCONN);C(service->beginFrame(session,1,counts(image()),7,true,true,true).code==ESTALE);C(service->beginFrame(session,-1,counts(image()),7,true,true,true).code==EINVAL);
 send(*service,session,0,image(),1);C(service->appendFrame(session,-1,0,{0}).code==EINVAL);C(service->appendFrame(session,0,-1,{0}).code==EINVAL);C(service->appendFrame(session,0,0,{0}).code==ESTALE);C(service->commitFrame(session,&generation).isOk()&&generation==1&&!held);C(!owner.snapshot(&output,(uint64_t*)&again));C(!output.permissions.get(10002,&mask)&&mask==4);
 C(service->beginFrame(session,0,counts(image()),7,true,true,true).code==ESTALE);send(*service,session,generation,image());C(service->abandonFrame(session).isOk()&&!held);C(service->commitFrame(session,&again).code==ENOTCONN);
 // Death while a frame is staged holds traffic and removes publication. A stale death from
 // that old binder must not revoke the new session, even after its next successful commit.
 send(*service,session,generation,image());auto oldDeaths=client->deaths;client->kill();C(held);uint64_t outGeneration=99;C(owner.snapshot(&output,&outGeneration)==-EAGAIN&&outGeneration==99);C(service->commitFrame(session,&again).code==ESTALE);
 auto nextClient=sp<IBinder>::make();int64_t nextSession=0;C(service->openSession(nextClient,1,&nextSession).isOk()&&nextSession>session);send(*service,nextSession,0,image());C(service->commitFrame(nextSession,&generation).isOk()&&generation==2&&!held);for(auto&d:oldDeaths)d->binderDied({});C(!held);C(service->abandonFrame(nextSession).isOk());
 // Repeated permission revocation/grant images advance exactly one generation each.
 for(int i=0;i<40;++i){auto v=image();v[Frame::RawPermissions][5]=i%2?4:0;send(*service,nextSession,generation,v,3);C(service->commitFrame(nextSession,&generation).isOk()&&generation==3+i);uint64_t g;C(!owner.snapshot(&output,&g)&&g==(uint64_t)generation);C(!output.permissions.get(10001,&mask)&&mask==(i%2?0u:4u));}
 nextClient->kill();C(held);C(owner.snapshot(&output,&outGeneration)==-EAGAIN);
 }
 // Every HOLD failure before/after actual fixture effect closes/holds the lease.
 for(bool after:{false,true})for(unsigned point=1;point<=2;++point){resetActive();AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));uint64_t g=0;C(!owner.replaceWithGeneration(desired(),0,&g)&&g==1);ioCount=0;ioFault=point;ioAfter=after;C(owner.suspendFrameworkClient()<0&&held&&files.empty());C(owner.snapshot(&output,&g)==-EAGAIN);}

 resetActive();{AccountingCombined kernel;P owner(kernel);uint64_t rawGeneration=777;C(owner.frameworkGeneration(&rawGeneration)==-ENOTCONN&&rawGeneration==777);C(owner.frameworkGeneration(nullptr)==-EINVAL);C(!owner.startWithAccounting(accountingProgram));C(!owner.frameworkGeneration(&rawGeneration)&&rawGeneration==0);auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=0,generation=777;C(service->openSession(client,1,&session).isOk());
 for(uint32_t uid:{0u,1001u,1051u,1073u,10000u,101000u,UINT32_MAX}){android::IPCThreadState::uid=uid;C(service->readGeneration(session,&generation).exception==-1&&generation==777);C(service->closeSession(client).exception==-1);}
 android::IPCThreadState::uid=1000;C(service->readGeneration(session+1,&generation).code==ESTALE&&generation==777);C(service->readGeneration(session,&generation).isOk()&&generation==0);C(service->closeSession(sp<IBinder>::make()).code==ESTALE);C(service->closeSession({}).code==ESTALE);
 // Simultaneous begins and repeated same-offset chunks are serialized without duplication.
 android::binder::Status first,second;
 std::thread a([&]{first=service->beginFrame(session,0,counts(image()),7,true,true,true);});std::thread b([&]{second=service->beginFrame(session,0,counts(image()),7,true,true,true);});a.join();b.join();C((first.isOk()&&second.code==EBUSY)||(second.isOk()&&first.code==EBUSY));
 std::thread c([&]{first=service->appendFrame(session,0,0,{0});});std::thread d([&]{second=service->appendFrame(session,0,0,{0});});c.join();d.join();C((first.isOk()&&second.code==ESTALE)||(second.isOk()&&first.code==ESTALE));C(service->abandonFrame(session).isOk());
 send(*service,session,0,image());C(service->commitFrame(session,&generation).isOk()&&generation==1&&!held);C(service->readGeneration(session,&generation).isOk()&&generation==1);auto oldDeaths=client->deaths;C(service->closeSession(client).isOk()&&held&&client->deaths.empty());C(service->readGeneration(session,&generation).code==ESTALE);C(service->closeSession(client).code==ESTALE);
 auto next=sp<IBinder>::make();int64_t nextSession=0;C(service->openSession(next,1,&nextSession).isOk()&&nextSession>session);C(service->readGeneration(nextSession,&generation).isOk()&&generation==0);send(*service,nextSession,0,image());C(service->commitFrame(nextSession,&generation).isOk()&&generation==2&&!held);for(auto&death:oldDeaths)death->binderDied({});C(!held);C(service->closeSession(client).code==ESTALE&&!held);C(service->closeSession(next).isOk()&&held);
 }
 // Commit vs death has two valid orderings, both finish held/unpublished.
 for(unsigned attempt=0;attempt<10;++attempt){resetActive();AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=0,generation=0;C(service->openSession(client,1,&session).isOk());send(*service,session,0,image());android::binder::Status result;std::thread a([&]{result=service->commitFrame(session,&generation);});std::thread b([&]{client->kill();});a.join();b.join();C(result.isOk()||result.code==ESTALE);C(held);uint64_t gen=777;C(owner.snapshot(&output,&gen)==-EAGAIN&&gen==777);}
 C(files.empty()&&held);printf("policy_frame_service_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
'''
(O/'test.cpp').write_text(code)
old_source=next(Path(v).parent for v in reference['command'] if v.endswith('/Gta3xlwifiSocketPolicyProjection.cpp'))
command=[v.replace(str(R),str(O)).replace(str(old_source),str(S)) for v in reference['command']]
command[1:1]=[str(S/'Gta3xlwifiPolicyFrame.cpp'),str(S/'Gta3xlwifiNetpolicyService.cpp')]
x=subprocess.run(command,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.search(r'policy_frame_service_cases=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
paths=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',O/'IptablesRestoreController.h',*S.glob('Gta3xlwifi*.h'),*[Path(v) for v in command if v.startswith(str(S)) and v.endswith('.cpp')],*(O/'binder').glob('*.h'),O/'com/android/internal/net/BnGta3xlwifiNetpolicy.h',*(S/'linux/netfilter').glob('*.h')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[2]),'frame_service_cases':int(m[1]),'all_seven_RPC_identity_checks':True,'generation_close_and_commit_death_races':True,'all_23026_provider_regressions_replayed':True,'full_known_uid_boundary':65536,'raw_permission_chunk_partitions':128,'all_RPC_identity_checks':True,'client_death_and_stale_death_checked':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':command,'real_Binder_executed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
