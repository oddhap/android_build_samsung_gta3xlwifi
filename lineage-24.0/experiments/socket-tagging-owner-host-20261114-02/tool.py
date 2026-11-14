#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual atomic tagging owner vs pinned migrated A17 authorization and limits.

Real owner/lease with syscall/rule fixtures and a trusted tag transport fixture.
Primary BpfHandler permission/charge guards run with explicit map fixtures.
Does not initialize a provider, tag real kernel sockets or declare Ready.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','reference-host','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();R=a.reference_host.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
h=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');sp=importlib.util.spec_from_file_location('extract',h);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==3250 and sha(R/'test.cpp')==r['inputs_sha256'][str(R/'test.cpp')]
old=(B/'Gta3xlwifiSocketPolicyProjection.cpp').read_text();new=(S/'Gta3xlwifiSocketPolicyProjection.cpp').read_text()
for name in re.findall(r'int SocketPolicyProjection::(\w+)\(',old):
 if name=='packetAccountingAvailableLocked':
  signature='int SocketPolicyProjection::packetAccountingAvailableLocked() const {'
  begin=old.index(signature);end=old.index('\n}',begin)+2;begin2=new.index(signature);end2=new.index('\n}',begin2)+2;assert old[begin:end]==new[begin2:end2]
 elif name!='readTaggingBudget':assert m.extract(old,'SocketPolicyProjection::'+name)==m.extract(new,'SocketPolicyProjection::'+name),name
prior_body=m.extract(old,'SocketPolicyProjection::readTaggingBudget').split('std::lock_guard<std::mutex> lock(mMutex);',1)[1].strip();new_body=m.extract(new,'SocketPolicyProjection::readTaggingBudgetLocked').split('{',1)[1].strip();assert prior_body==new_body
handler=A/'packages/modules/Connectivity/bpf/netd/BpfHandler.cpp';netdh=A/'packages/modules/Connectivity/bpf/progs/netd.h';aids=A/'system/core/libcutils/include/private/android_filesystem_config.h';ht=handler.read_text();nt=netdh.read_text();ids=aids.read_text()
permission=m.extract(ht,'BpfHandler::hasUpdateDeviceStatsPermission');tag=m.extract(ht,'BpfHandler::tagSocket');guard=tag[tag.index('{')+1:tag.index('    // The socket destroy listener')]
defines=''
for name in ['PERMISSION_COUNT','UIDS_PER_INT64','CHUNK_INT64_COUNT','CHUNK_UID_COUNT','PERMISSION_BIT_UPDATE_DEVICE_STATS']:
 match=re.search(r'^#define '+name+r'\s+[^\n]+',nt,re.M);assert match;defines+=match[0]+'\n'
for name in ['AID_ROOT','AID_SYSTEM','AID_DNS','AID_CLAT','AID_USER_OFFSET']:
 match=re.search(r'^#define '+name+r'\s+([0-9]+)\b',ids,re.M);assert match;defines+='#define '+name+' '+match[1]+'\n'
chunk=nt[nt.index('struct UidPermissionChunk {'):nt.index('};',nt.index('struct UidPermissionChunk {'))+2]
code=(R/'test.cpp').read_text().replace('int main(){','static int active_regressions(){',1)
code+='\n#include <atomic>\n#include <thread>\n'+defines+'\n'+chunk+r'''
namespace Oracle {
static uint32_t uid,mask;
constexpr uint32_t BPF_PERMISSION_UPDATE_DEVICE_STATS=8;
template<class T>struct Result{T data;bool ok()const{return true;}T value()const{return data;}};
struct Migration{Result<bool>readValue(uint32_t key){assert(key==0);return {true};}};
struct Chunk{Result<UidPermissionChunk>readValue(uint32_t key){assert(key==uid/CHUNK_UID_COUNT);UidPermissionChunk value{};value.block[uid/UIDS_PER_INT64%CHUNK_INT64_COUNT]=uint64_t(mask)<<((uid%UIDS_PER_INT64*PERMISSION_COUNT)&63);return {value};}};
struct Legacy{Result<uint32_t>readValue(uint32_t){assert(false);return {0};}};
struct Cookies{bool isValid(){return true;}};
struct BpfHandler{Migration mUidMigrationEnabledMap;Chunk mUidPermissionChunkMap;Legacy mUidPermissionMap;Cookies mCookieTagMap;bool hasUpdateDeviceStatsPermission(uid_t);int authorize(uint32_t chargeUid,uint32_t realUid);};
'''+permission+'\nint BpfHandler::authorize(uint32_t chargeUid,uint32_t realUid){'+guard+'return 0;}\n}\n'+r'''
struct Tagger:android::net::gta3xlwifi::SocketTagger{
 bool alive=true,drop=false;int result=0;unsigned tags=0,untags=0;uint32_t lastTag=0,lastUid=0;int lastFd=-1;std::function<void()> onTag;
 bool connected()const override{return alive;}
 int tagSocket(int fd,uint32_t tag,uid_t uid)override{assert(alive&&!held);++tags;lastTag=tag;lastUid=uid;lastFd=fd;if(onTag)onTag();if(drop)alive=false;return result;}
 int untagSocket(int fd)override{assert(alive&&!held);++untags;lastFd=fd;if(drop)alive=false;return result;}
};
static void budgetRows(unsigned total,unsigned perUid,uint32_t charge){activeEntries.clear();for(unsigned i=0;i<perUid;i++)activeEntries.push_back({{charge,i,0,17},0,0,0,0});for(unsigned i=perUid;i<total;i++)activeEntries.push_back({{uint32_t(charge+1),i,0,17},0,0,0,0});}
int main(){
 C(active_regressions()==0);unsigned begin=cases,oracleCases=0;
 resetActive();{AccountingCombined k;P p(k);Tagger t;C(p.tagSocket(t,-1,0,1,1)==-EINVAL&&p.tagSocket(t,9,0,-1,1)==-EINVAL&&p.tagSocket(t,9,0,1,-1)==-EINVAL&&p.untagSocket(t,-1)==-EINVAL&&ioCount==0);C(p.tagSocket(t,9,0,1,1)==-EAGAIN&&p.untagSocket(t,9)==-EAGAIN&&!t.tags&&!t.untags);C(p.startWithAccounting(accountingProgram)==0&&p.tagSocket(t,9,0,1,1)==-EAGAIN);C(p.replace(desired(),0)==0);C(p.tagSocket(t,9,UINT32_MAX,1,1)==0&&t.lastTag==UINT32_MAX&&t.lastUid==1&&t.lastFd==9);C(p.untagSocket(t,9)==0&&t.untags==1);}
 for(int32_t real:{0,1000,1051,1029,10001,10002,100000,101000,101051,110001,201051,INT32_MAX}){
  resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);
  for(unsigned mask=0;mask<128;mask++){
   C(p.setUidPermission(real,mask)==0);Oracle::uid=real;Oracle::mask=mask;Oracle::BpfHandler oracle;
   for(int32_t charge:{real,10001,10002,1029,110001}){auto before=t.tags;auto points=ioCount;int expected=oracle.authorize(charge,real);int result=p.tagSocket(t,9,7,charge,real);C(result==expected&&!held&&opens==1);C(t.tags==before+(expected==0));if(expected)C(ioCount==points);++oracleCases;}
  }
 }
 for(auto pair:{std::pair<unsigned,unsigned>{0,0},{500,500},{501,501},{4500,500},{4501,500},{4500,501},{5000,1}}){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);budgetRows(pair.first,pair.second,10001);auto before=t.tags;int expected=pair.first>4500||pair.second>500?-EMFILE:0;C(p.tagSocket(t,9,7,10001,10001)==expected&&!held);C(t.tags==before+(expected==0));}
 for(int error:{-EBADF,-ENOTSOCK,-EAFNOSUPPORT,-EPROTONOSUPPORT,-EMFILE,-EINVAL,-EPERM,-EIO}){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);t.result=error;C(p.tagSocket(t,9,7,1,1)==error&&!held&&opens==1);C(p.untagSocket(t,9)==error&&!held);t.result=0;C(p.tagSocket(t,9,7,1,1)==0&&!held);}
 for(bool untag:{false,true})for(int error:{0,-EIO,1}){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);t.result=error;t.drop=true;int result=untag?p.untagSocket(t,9):p.tagSocket(t,9,7,1,1);C(result==(error<0?error:-EPROTO)&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 for(bool untag:{false,true}){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);t.alive=false;C((untag?p.untagSocket(t,9):p.tagSocket(t,9,7,1,1))==-ENOTCONN&&held&&files.empty()&&!t.tags&&!t.untags);}
 for(bool after:{false,true})for(unsigned i=1;i<=5;i++){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);ioCount=0;ioFault=i;ioAfter=after;C(p.tagSocket(t,9,7,1,1)<0&&held&&files.empty()&&!t.tags);}
 resetActive();{AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0&&p.setUidPermission(10001,2)==0);std::atomic<bool> attempted=false,done=false;std::thread writer;t.onTag=[&]{writer=std::thread([&]{attempted=true;assert(!p.setUidPermission(10001,0));done=true;});while(!attempted.load())std::this_thread::yield();assert(!done.load());};C(p.tagSocket(t,9,7,10002,10001)==0);writer.join();C(done.load());t.onTag={};auto before=t.tags;C(p.tagSocket(t,9,7,10002,10001)==-EPERM&&t.tags==before&&!held);}
 C(files.empty()&&held&&oracleCases==7680);printf("tagging_owner_cases=%u oracle_comparisons=%u total_cases=%u\n",cases-begin,oracleCases,cases);return 0;
}
'''
(O/'test.cpp').write_text(code);shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h');cmd=[x.replace(str(R),str(O)).replace(str(B),str(S)) for x in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.search(r'tagging_owner_cases=(\d+) oracle_comparisons=(\d+) total_cases=(\d+)\n$',x.stdout);assert match
paths=[Path(__file__),h,handler,netdh,aids,R/'report.json',R/'test.cpp',O/'test.cpp',O/'IptablesRestoreController.h',S/'projection-guards.inc',*S.glob('Gta3xlwifi*.h'),*[Path(x) for x in cmd if x.startswith(str(S)) and x.endswith('.cpp')]]
d={k:v for k,v in r.items() if k not in ['scope','passed_cases','inputs_sha256','command']};d.update(passed=True,scope=__doc__,passed_cases=int(match[3]),tagging_owner_cases=int(match[1]),primary_A17_authorization_comparisons=int(match[2]),permission_budget_tag_under_one_mutex=True,inputs_sha256={str(p):sha(p) for p in paths},command=cmd,stderr=x.stderr)
(O/'report.json').write_text(json.dumps(d,indent=2)+'\n');print(x.stdout.strip())
