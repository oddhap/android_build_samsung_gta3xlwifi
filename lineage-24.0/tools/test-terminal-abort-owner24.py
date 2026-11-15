#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual token+session terminal abort and all previous owner/receipt regressions.

Production fatal dispatch is captured by the existing host boundary fixture;
no Android, host daemon, zygote, device or build process is terminated.
"""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==26494
for n,h in r['inputs_sha256'].items():assert sha(Path(n))==h
for n in ['binder','com']:shutil.copytree(R/n,O/n)
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
f=O/'com/android/internal/net/BnGta3xlwifiNetpolicy.h';s=f.read_text().replace('};}', ' virtual ::android::binder::Status abortSession(int64_t,const ::android::sp<::android::IBinder>&)=0;\n};}');f.write_text(s)
code=(R/'test.cpp').read_text().replace('int main(int argc,char**argv)', 'static int previous_abort_regressions(int argc,char**argv)',1)
code+=r'''
int main(int argc,char**argv){C(!previous_abort_regressions(argc,argv));unsigned begin=cases;
 resetNonce();{AccountingCombined kernel;P p(kernel);C(!p.startWithAccounting(accountingProgram));auto service=sp<Service>::make(p);auto token=sp<IBinder>::make();auto other=sp<IBinder>::make();int64_t session=0,g=0;C(service->openSession(token,1,&session).isOk());send(*service,session,0,image());C(service->commitFrame(session,&g).isOk());unsigned fatalBefore=fatalCalls;auto ioBefore=ioCount;
 for(uint32_t uid:{0u,1001u,1051u,10000u,101000u,UINT32_MAX}){android::IPCThreadState::uid=uid;C(service->abortSession(session,token).exception==-1&&fatalCalls==fatalBefore&&ioCount==ioBefore&&!held);}android::IPCThreadState::uid=1000;
 C(service->abortSession(session+1,token).code==ESTALE&&fatalCalls==fatalBefore);C(service->abortSession(session,other).code==ESTALE&&fatalCalls==fatalBefore);C(service->abortSession(session,sp<IBinder>{}).code==ESTALE&&fatalCalls==fatalBefore);
 C(service->closeSession(token).isOk()&&fatalCalls==fatalBefore&&held);int64_t replacement=0;C(service->openSession(token,1,&replacement).isOk()&&replacement!=session);send(*service,replacement,0,image());C(service->commitFrame(replacement,&g).isOk()&&!held);auto replacementIo=ioCount;C(service->abortSession(session,token).code==ESTALE&&fatalCalls==fatalBefore&&ioCount==replacementIo&&!held);C(service->abortSession(replacement,other).code==ESTALE&&fatalCalls==fatalBefore&&ioCount==replacementIo&&!held);
 C(service->abortSession(replacement,token).code==ECONNABORTED&&fatalCalls==fatalBefore+1&&fatalError==-ECONNABORTED&&held&&files.empty());uint64_t gen=99;C(p.frameworkGeneration(&gen)==-ENOTCONN&&gen==99);}
 resetNonce();{AccountingCombined kernel;P p(kernel);C(!p.startWithAccounting(accountingProgram));unsigned before=fatalCalls;C(!p.suspendFrameworkClient()&&fatalCalls==before);p.stop();C(fatalCalls==before&&held&&files.empty());}
 printf("terminal_abort_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);old=next(Path(v).parent for v in r['command'] if v.endswith('/Gta3xlwifiSocketPolicyProjection.cpp'));cmd=[v.replace(str(R),str(O)).replace(str(old),str(S)) for v in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test'),str(O/'names-wire.txt')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'terminal_abort_cases=(\d+) total_cases=(\d+)\n$',x.stdout);assert m
inputs=[Path(__file__),R/'report.json',R/'test.cpp',O/'test.cpp',f,*[p for p in S.rglob('*') if p.is_file()]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[2]),'terminal_abort_cases':int(m[1]),'stale_session_cannot_abort_reused_token':True,'normal_close_suspend_stop_nonfatal':True,'command':cmd,'inputs_sha256':{str(p):sha(p) for p in inputs},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
