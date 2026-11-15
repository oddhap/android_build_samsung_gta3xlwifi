#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual owner/service cleanup with kernel/socket-delete boundary fixtures.

Replays26339 prior assertions. Provider identity dispatch is copied verbatim;
the transport's proc implementation is tested separately, not simulated Ready.
"""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==26339
for n,h in r['inputs_sha256'].items():assert sha(Path(n))==h
for n in ['binder','com']:shutil.copytree(R/n,O/n)
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
f=O/'com/android/internal/net/BnGta3xlwifiNetpolicy.h';t=f.read_text().replace('};}', ' virtual ::android::binder::Status removeUidAccounting(int64_t,int32_t,int64_t,int64_t)=0;\n};}');assert 'virtual ::android::binder::Status removeUidAccounting' in t;f.write_text(t)
code=(R/'test.cpp').read_text();code=code.replace('static unsigned largeStatsRows;', '''static bool cleanupFixture=false;static uint32_t cleanupPending=0;static uint64_t cleanupEpoch=1;
static std::vector<std::string>cleanupEvents;static int deleteResult=0;static bool failAfterTags=false;
static unsigned largeStatsRows;''',1)
needle='x->total_stats_lost=UINT64_MAX;';assert code.count(needle)==1;code=code.replace(needle,needle+'''if(cleanupFixture){x->active_epoch=cleanupEpoch;x->bank_epoch[0]=cleanupEpoch;x->pending_mask=cleanupPending;if(cleanupPending)x->bank_epoch[1]=cleanupEpoch;cleanupEvents.push_back("state");}''')
needle='else{auto*x=reinterpret_cast<gta3xlwifi_packet_stats_edit*>(arg);';assert code.count(needle)==1;code=code.replace(needle,needle+'''if(cleanupFixture&&x->operation==GTA3XLWIFI_STATS_DELETE_UID)cleanupEvents.push_back("counters");''')
code=code.replace('int main(int argc,char**argv)','static int previous_cleanup_regressions(int argc,char**argv)',1)
provider=(S/'Gta3xlwifiHeldProvider.cpp').read_text();start=provider.index('int removeUidAccountingFromProvider(');end=provider.index('int checkHeldProviderStartup(',start);provider=provider[start:end]
code+=r'''
static int deleteUidFixture(uint32_t uid){C(uid==123);cleanupEvents.push_back("tags");if(failAfterTags){packetError=1;packetErrno=EIO;}return deleteResult;}
namespace android::net::gta3xlwifi {
static SocketPolicyProjection* owner=nullptr;
static int deleteTags(uint32_t uid){return deleteUidFixture(uid);}
'''+provider+r'''
}
static void resetCleanup(){resetNames();cleanupFixture=true;cleanupPending=0;cleanupEpoch=1;cleanupEvents.clear();deleteResult=0;failAfterTags=false;android::net::gta3xlwifi::owner=nullptr;android::IPCThreadState::uid=1000;}
int main(int argc,char**argv){C(!previous_cleanup_regressions(argc,argv));unsigned begin=cases;
 resetCleanup();{AccountingCombined kernel;P p(kernel);C(p.removeUidAccounting(123,0,1,deleteUidFixture)==-EAGAIN&&cleanupEvents.empty());C(p.removeUidAccounting(-1,0,1,deleteUidFixture)==-EINVAL);C(p.removeUidAccounting(123,0,0,deleteUidFixture)==-EINVAL);C(p.removeUidAccounting(123,0,1,nullptr)==-EINVAL);C(!p.startWithAccounting(accountingProgram)&&held);C(p.removeUidAccounting(123,1,1,deleteUidFixture)==-ESTALE&&cleanupEvents.empty());C(p.removeUidAccounting(123,0,2,deleteUidFixture)==-ESTALE&&cleanupEvents==std::vector<std::string>{"state"});cleanupEvents.clear();cleanupPending=2;C(p.removeUidAccounting(123,0,1,deleteUidFixture)==-EBUSY&&held&&cleanupEvents==std::vector<std::string>{"state"});cleanupPending=0;cleanupEvents.clear();C(!p.removeUidAccounting(123,0,1,deleteUidFixture)&&held);C(cleanupEvents==std::vector<std::string>({"state","tags","counters"}));uint64_t g=99;C(!p.frameworkGeneration(&g)&&g==0);C(!p.replace(desired(),0)&&!held);cleanupEvents.clear();C(p.removeUidAccounting(123,0,1,deleteUidFixture)==-ESTALE&&cleanupEvents.empty());C(!p.removeUidAccounting(123,1,1,deleteUidFixture)&&!held);}
 resetCleanup();{AccountingCombined kernel;P p(kernel);C(!p.start()&&!p.replace(desired(),0));C(p.removeUidAccounting(123,1,1,deleteUidFixture)==-EOPNOTSUPP&&cleanupEvents.empty());}
 for(int result:{-EIO,-EPERM,1}){resetCleanup();AccountingCombined kernel;P p(kernel);C(!p.startWithAccounting(accountingProgram)&&!p.replace(desired(),0));deleteResult=result;C(p.removeUidAccounting(123,1,1,deleteUidFixture)==(result<0?result:-EPROTO));C(held&&files.empty()&&cleanupEvents==std::vector<std::string>({"state","tags"}));}
 resetCleanup();{AccountingCombined kernel;P p(kernel);C(!p.startWithAccounting(accountingProgram)&&!p.replace(desired(),0));failAfterTags=true;C(p.removeUidAccounting(123,1,1,deleteUidFixture)==-EIO&&held&&files.empty());C(cleanupEvents==std::vector<std::string>({"state","tags","counters"}));}
 resetCleanup();{AccountingCombined kernel;P p(kernel);C(!p.startWithAccounting(accountingProgram));packetBad=true;C(p.removeUidAccounting(123,0,1,deleteUidFixture)==-EPROTO&&held&&files.empty());C(cleanupEvents==std::vector<std::string>{"state"});}
 resetCleanup();{AccountingCombined kernel;P p(kernel);C(!p.startWithAccounting(accountingProgram));held=false;C(p.removeUidAccounting(123,0,1,deleteUidFixture)==-EUCLEAN&&held&&files.empty()&&cleanupEvents.empty());}
 resetCleanup();{AccountingCombined kernel;P p(kernel);C(!p.startWithAccounting(accountingProgram));auto service=sp<Service>::make(p);auto token=sp<IBinder>::make();int64_t session=0;C(service->openSession(token,1,&session).isOk());android::net::gta3xlwifi::owner=&p;cleanupEvents.clear();
 for(uint32_t uid:{0u,1001u,1051u,10000u,101000u,UINT32_MAX}){android::IPCThreadState::uid=uid;C(service->removeUidAccounting(session,123,0,1).exception==-1&&cleanupEvents.empty());}android::IPCThreadState::uid=1000;
 C(service->removeUidAccounting(session+1,123,0,1).code==ESTALE&&cleanupEvents.empty());C(service->removeUidAccounting(session,-1,0,1).code==EINVAL);C(service->removeUidAccounting(session,123,-1,1).code==EINVAL);C(service->removeUidAccounting(session,123,0,0).code==EINVAL);
 C(service->removeUidAccounting(session,123,0,1).isOk()&&held);C(cleanupEvents==std::vector<std::string>({"state","tags","counters"}));cleanupEvents.clear();android::net::gta3xlwifi::owner=nullptr;C(service->removeUidAccounting(session,123,0,1).code==ENOTCONN&&cleanupEvents.empty());}
 printf("uid_cleanup_owner_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);old=next(Path(v).parent for v in r['command'] if v.endswith('/Gta3xlwifiSocketPolicyProjection.cpp'));cmd=[v.replace(str(R),str(O)).replace(str(old),str(S)) for v in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test'),str(O/'names-wire.txt')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'uid_cleanup_owner_cases=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
inputs=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',O/'com/android/internal/net/BnGta3xlwifiNetpolicy.h',*[p for p in S.rglob('*') if p.is_file()]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[2]),'uid_cleanup_owner_cases':int(m[1]),'exact_provider_identity_method_executed':True,'UID_reuse_and_durable_NSS_lifecycle_integrated':False,'command':cmd,'inputs_sha256':{str(p):sha(p) for p in inputs},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
