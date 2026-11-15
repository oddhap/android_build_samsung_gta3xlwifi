#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual nonce owner/service/lease over explicit packet-store/receipt/socket fixtures."""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==26401
for n,h in r['inputs_sha256'].items():assert sha(Path(n))==h
for n in ['binder','com']:shutil.copytree(R/n,O/n)
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
p=O/'com/android/internal/net/BnGta3xlwifiNetpolicy.h';s=p.read_text().replace('};}', ' virtual ::android::binder::Status removeUidAccountingOnce(int64_t,int32_t,int64_t,int64_t,int64_t)=0;\n};}');p.write_text(s)
code=(R/'test.cpp').read_text();assert code.count('for(int kind:{-1,5})')==1;code=code.replace('for(int kind:{-1,5})','for(int kind:{-1,6})')
code=code.replace('extern "C" int __wrap_ioctl(', 'extern "C" int receiptBaseIoctl(',1).replace('int main(int argc,char**argv)', 'static int previous_nonce_regressions(int argc,char**argv)',1)
provider=(S/'Gta3xlwifiHeldProvider.cpp').read_text();start=provider.index('int removeUidAccountingOnceFromProvider(');end=provider.index('int checkHeldProviderStartup(',start);provider=provider[start:end]
code+=r'''
static gta3xlwifi_uid_cleanup receiptStore{};static unsigned receiptCalls,receiptCommits;
static int receiptFaultOp=-1,receiptFaultErr=0,receiptMalformed=0,receiptPositive=0;static unsigned reusedUidRows;
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);if(cmd!=GTA3XLWIFI_UID_CLEANUP)return receiptBaseIoctl(fd,cmd,arg);
 assert(files.count(fd)&&arg);++receiptCalls;auto*q=reinterpret_cast<gta3xlwifi_uid_cleanup*>(arg);assert(q->version==1&&!q->phase);for(auto r:q->reserved)assert(!r);auto request=*q;cleanupEvents.push_back(request.operation==0?"receipt-read":request.operation==1?"receipt-begin":"receipt-commit");
 if(int(request.operation)==receiptFaultOp){errno=receiptFaultErr;return -1;}
 if(request.operation==0){assert(!request.uid&&!request.nonce&&!request.generation&&!request.active_epoch);}
 else if(request.operation==1){if(receiptStore.phase&&receiptStore.nonce==request.nonce){assert(receiptStore.uid==request.uid&&receiptStore.generation==request.generation&&receiptStore.active_epoch==request.active_epoch);if(receiptStore.phase==1){errno=EINPROGRESS;return -1;}}else{receiptStore=request;receiptStore.phase=1;}}
 else if(request.operation==2){assert(receiptStore.phase==1&&receiptStore.nonce==request.nonce&&receiptStore.uid==request.uid);receiptStore.phase=2;receiptCommits++;reusedUidRows=0;}else assert(false);
 *q=receiptStore;q->version=1;q->operation=request.operation;
 switch(receiptMalformed){case 0:break;case 1:q->version=2;break;case 2:q->operation=99;break;case 3:q->phase=3;break;case 4:q->uid=0x80000000U;break;case 5:q->reserved[5]=1;break;case 6:q->nonce=0;break;case 7:q->active_epoch=0;break;case 8:q->generation++;break;default:assert(false);}return receiptPositive;
}
namespace android::net::gta3xlwifi {
'''+provider+r'''
}
static void resetNonce(){resetCleanup();features|=GTA3XLWIFI_UID_CAP_UID_CLEANUP_RECEIPT;receiptStore={};receiptCalls=receiptCommits=0;receiptFaultOp=-1;receiptFaultErr=receiptMalformed=receiptPositive=0;reusedUidRows=3;}
int main(int argc,char**argv){C(!previous_nonce_regressions(argc,argv));unsigned begin=cases;
 resetNonce();{AccountingCombined k;P p(k);NetpolicyLease::UidCleanupReceipt out;C(p.readUidCleanup(&out)==-EAGAIN&&receiptCalls==0);C(!p.startWithAccounting(accountingProgram)&&held);C(!p.readUidCleanup(&out)&&out.phase==0&&!out.nonce&&held);C(!p.replace(desired(),0));cleanupEvents.clear();C(!p.removeUidAccountingOnce(123,1,1,7,deleteUidFixture));C(cleanupEvents==std::vector<std::string>({"receipt-read","state","receipt-begin","tags","receipt-commit"})&&receiptCommits==1&&reusedUidRows==0);reusedUidRows=9;cleanupEvents.clear();C(!p.removeUidAccountingOnce(123,1,1,7,deleteUidFixture)&&reusedUidRows==9&&receiptCommits==1);C(cleanupEvents==std::vector<std::string>{"receipt-read"});C(p.removeUidAccountingOnce(124,1,1,7,deleteUidFixture)==-ESTALE&&reusedUidRows==9);C(p.removeUidAccountingOnce(123,2,1,7,deleteUidFixture)==-ESTALE);C(p.removeUidAccountingOnce(123,1,2,7,deleteUidFixture)==-ESTALE);C(p.removeUidAccountingOnce(123,1,1,6,deleteUidFixture)==-ESTALE);C(!p.suspendFrameworkClient()&&held);C(!p.removeUidAccountingOnce(123,1,1,7,deleteUidFixture)&&held&&reusedUidRows==9);uint64_t gen=99;C(!p.frameworkGeneration(&gen)&&gen==0);}
 resetNonce();{AccountingCombined k;P p(k);C(!p.startWithAccounting(accountingProgram));C(p.removeUidAccountingOnce(123,0,1,0,deleteUidFixture)==-EINVAL&&receiptCalls==0);C(p.removeUidAccountingOnce(123,0,1,1,nullptr)==-EINVAL&&receiptCalls==0);C(p.removeUidAccountingOnce(123,1,1,1,deleteUidFixture)==-ESTALE);cleanupPending=2;C(p.removeUidAccountingOnce(123,0,1,1,deleteUidFixture)==-EBUSY&&receiptStore.phase==0);cleanupPending=0;C(!p.removeUidAccountingOnce(123,0,1,1,deleteUidFixture)&&held);}
 for(int op:{0,1,2}){resetNonce();AccountingCombined k;P p(k);C(!p.startWithAccounting(accountingProgram));receiptFaultOp=op;receiptFaultErr=op==0?EIO:EINTR;C(p.removeUidAccountingOnce(123,0,1,1,deleteUidFixture)==-receiptFaultErr&&held&&files.empty());C(op==0?receiptCalls==1:receiptCalls==unsigned(op+1));}
 for(int error:{EIO,EPERM}){resetNonce();AccountingCombined k;P p(k);C(!p.startWithAccounting(accountingProgram));deleteResult=-error;C(p.removeUidAccountingOnce(123,0,1,1,deleteUidFixture)==-error&&receiptStore.phase==1&&held&&files.empty()&&!receiptCommits);}
 resetNonce();{AccountingCombined k;P p(k);C(!p.startWithAccounting(accountingProgram));receiptStore={1,1,1,123,9,0,1,{}};C(p.removeUidAccountingOnce(123,0,1,9,deleteUidFixture)==-EINPROGRESS&&held&&files.empty()&&!receiptCommits);}
 for(int bad=1;bad<=7;++bad){resetNonce();AccountingCombined k;P p(k);C(!p.startWithAccounting(accountingProgram));receiptStore={1,2,2,123,1,0,1,{}};receiptMalformed=bad;C(p.removeUidAccountingOnce(123,0,1,1,deleteUidFixture)==-EPROTO&&held&&files.empty());}
 resetNonce();{AccountingCombined k;P p(k);C(!p.startWithAccounting(accountingProgram));features&=~GTA3XLWIFI_UID_CAP_UID_CLEANUP_RECEIPT;NetpolicyLease::UidCleanupReceipt out;C(p.readUidCleanup(&out)==-EOPNOTSUPP&&held&&files.empty()&&!receiptCalls);}
 resetNonce();{AccountingCombined k;P p(k);C(!p.startWithAccounting(accountingProgram));auto service=sp<Service>::make(p);auto token=sp<IBinder>::make();int64_t session=0;C(service->openSession(token,1,&session).isOk());android::net::gta3xlwifi::owner=&p;std::vector<int64_t>out{99};
 for(uint32_t uid:{0u,1001u,1051u,10000u,101000u}){android::IPCThreadState::uid=uid;auto before=receiptCalls;C(service->readStats(session,5,0,0,&out).exception==-1&&receiptCalls==before);C(service->removeUidAccountingOnce(session,123,0,1,1).exception==-1&&receiptCalls==before);}android::IPCThreadState::uid=1000;
 C(service->readStats(session+1,5,0,0,&out).code==ESTALE);C(service->removeUidAccountingOnce(session+1,123,0,1,1).code==ESTALE);C(service->removeUidAccountingOnce(session,123,0,1,0).code==EINVAL);C(service->readStats(session,5,1,0,&out).code==EINVAL);C(service->readStats(session,5,0,1,&out).code==EINVAL);
 C(service->readStats(session,5,0,0,&out).isOk()&&out==std::vector<int64_t>({1,5,0,0,0,0,0})&&held);C(service->removeUidAccountingOnce(session,123,0,1,11).isOk()&&held);C(service->readStats(session,5,0,0,&out).isOk()&&out==std::vector<int64_t>({1,5,2,123,11,0,1}));}
 printf("uid_receipt_owner_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);old=next(Path(v).parent for v in r['command'] if v.endswith('/Gta3xlwifiSocketPolicyProjection.cpp'));cmd=[v.replace(str(R),str(O)).replace(str(old),str(S)) for v in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test'),str(O/'names-wire.txt')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'uid_receipt_owner_cases=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
inputs=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',O/'com/android/internal/net/BnGta3xlwifiNetpolicy.h',*[p for p in S.rglob('*') if p.is_file()]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[2]),'uid_receipt_owner_cases':int(m[1]),'completed_cache_precedes_current_generation_fence':True,'no_redelete_after_UID_reuse_or_publication_withdrawal':True,'command':cmd,'inputs_sha256':{str(p):sha(p) for p in inputs},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
