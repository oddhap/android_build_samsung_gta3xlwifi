#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Typed private ingress I/O/compiler/root verification vs actual A17 C oracle.

Syscalls/tables are fixtures. The separately compiled C oracle is hash-bound to
prior real Android17 comparisons. This validates extra predicates/control state,
not real packet execution, complete backend publication or network readiness.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','oracle-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();H=a.oracle_host.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-socket-roots24.py');subprocess.run(['python3',str(helper),'--source',str(S),'--output',str(O/'roots-regression')],check=True)
shutil.copyfile(O/'roots-regression/IptablesRestoreController.h',O/'IptablesRestoreController.h')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();prior=H/'report.json';r=json.loads(prior.read_text());assert r['passed'];oracle=H/'test.c';assert sha(oracle)==r['inputs_sha256'][str(oracle)]
c=oracle.read_text().replace('int main(void){','static int oracle_regression_main(void){',1);pos=c.rfind('}');c=c[:pos]+'return 0;'+c[pos:]
c+=r'''
int g24OracleChecks(void){return oracle_regression_main();}
int g24OracleIif(uint32_t flags,uint32_t allowed,uint32_t index,int is_dns,int is_output){
 protect=false;uid_entry=(UidOwnerValue){flags,allowed};struct __sk_buff s={index};struct gta3xlwifi_packet p={0};
 int verdict=bpf_owner_match(&p,&s,10001,(struct egress_bool){is_output},(struct kver_uint){(4<<16)|(19<<8)},(struct sdk_level_uint){0});
 return verdict==DROP||(verdict==DROP_UNLESS_DNS&&!is_dns);
}
int g24OracleDiscard(const uint8_t*configured,const uint8_t*actual,uint32_t first,uint32_t second,uint32_t index,int is_output,unsigned version){
 protect=true;memcpy(&protected_addr,configured,16);protected_iif=(IngressDiscardValue){{first,second}};struct __sk_buff s={index};struct gta3xlwifi_packet p={0};p.ip_version=version;memcpy(&p.daddr,actual,16);
 return !is_output&&index!=1&&ingress_should_discard(&p,&s,(struct kver_uint){(4<<16)|(19<<8)});
}
''';(O/'oracle.c').write_text(c)
cc=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(H/'include'),'-c',str(O/'oracle.c'),'-o',str(O/'oracle.o')];x=subprocess.run(cc,capture_output=True,text=True);(O/'oracle-compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
code=(O/'roots-regression/test.cpp').read_text().split('int main(){',1)[0]
# Extend only the fixture's kernel formatter/command effects; actual typed
# encode/parse/compiler/root/lease implementations are separately compiled.
needle=' if(r.verdict==X::Verdict::Return)';assert needle in code
code=code.replace(needle,r''' if(r.ingressIfIndex)s+=" -m gta3xlwifi_bad_iif --allowed-iif "+std::to_string(*r.ingressIfIndex);
 if(r.ingressDiscard){const auto&d=*r.ingressDiscard;s+=" -m gta3xlwifi_ingress_discard --ingress-daddr ";for(unsigned char b:d.daddr){char h[3];snprintf(h,3,"%02x",b);s+=h;}s+=" --allowed-iif1 "+std::to_string(d.allowedIfIndex[0])+" --allowed-iif2 "+std::to_string(d.allowedIfIndex[1]);}
'''+needle)
needle='   else assert(false);';assert code.count(needle)==1
code=code.replace(needle,r'''   else if(line.front()==':'){auto name=line.substr(1,line.find(' ')-1);assert(t.chains.count(name));t.chains[name].clear();}
   else if(line.rfind("-A ",0)==0){auto name=line.substr(3,line.find(' ',3)-3);assert(t.chains.count(name));t.chains[name].push_back(line);}
'''+needle)
code+=r'''
#include "Gta3xlwifiIngressPolicy.h"
extern "C" int g24OracleChecks();extern "C" int g24OracleIif(uint32_t,uint32_t,uint32_t,int,int);extern "C" int g24OracleDiscard(const uint8_t*,const uint8_t*,uint32_t,uint32_t,uint32_t,int,unsigned);
using IP=IngressPolicy;
RootImage ordinary(){UidPolicy policy;RootImage image;assert(UidChainProgram::ordinary(policy,&image)==0&&OrdinaryDispatch::append(&image)==0);return image;}
IP::Address address(unsigned n){IP::Address a{};a[0]=0x20;a[1]=1;a[14]=n>>8;a[15]=n;return a;}
bool evaluate(const RootImage&v,uint32_t uid,uint32_t iif,bool dns,bool output,const IP::Address&dst,unsigned version=6){
 if(output||iif==1)return false;
 for(auto&r:v[9].rules){
  if(r.ingressDiscard&&version&&dst==r.ingressDiscard->daddr&&iif!=r.ingressDiscard->allowedIfIndex[0]&&iif!=r.ingressDiscard->allowedIfIndex[1])return true;
  if(r.ingressIfIndex&&!dns&&r.uid->first<=uid&&uid<=r.uid->last&&(!*r.ingressIfIndex||*r.ingressIfIndex!=iif))return true;
 }return false;
}
int main(){
 C(g24OracleChecks()==0);unsigned comparisons=0;const auto base=ordinary();IP state;RootImage out=base;
 C(state.compile(base,&out)==0&&out==base);C(state.setIif(-1,1)==-EINVAL&&state.setIif(1,UINT32_MAX)==-EINVAL&&state.clearIif(-1)==-EINVAL&&state.setLockdown(-1,true)==-EINVAL&&state.removeUid(-1)==-EINVAL);
 C(state.setIif(10001,0)==0&&state.setLockdown(10001,true)==0&&state.compile(base,&out)==0&&out==base);C(state.clearIif(10001)==0&&state.compile(base,&out)==0&&out!=base&&out[9].rules[11].ingressIfIndex==std::optional<uint32_t>{0});C(state.setIif(10001,17)==0&&state.compile(base,&out)==0&&out[9].rules[11].ingressIfIndex==std::optional<uint32_t>{17});C(state.removeUid(10001)==0&&state.compile(base,&out)==0&&out==base);
 for(unsigned present=0;present<2;present++)for(unsigned lockdown=0;lockdown<2;lockdown++)for(uint32_t allowed:{0u,2u,17u}){
  IP model;if(present)assert(model.setIif(10001,allowed)==0);assert(model.setLockdown(10001,lockdown)==0);RootImage compiled;C(model.compile(base,&compiled)==0&&compiled[10]==base[10]);
  for(uint32_t uid:{10001u,10002u,110001u})for(uint32_t iif:{0u,1u,2u,17u,2147483647u})for(bool dns:{false,true})for(bool output:{false,true}){
   unsigned flags=uid==10001?((present?128:0)|(lockdown?256:0)):0;assert(evaluate(compiled,uid,iif,dns,output,address(9))==bool(g24OracleIif(flags,allowed,iif,dns,output)));++comparisons;
  }
 }
 IP discard;C(discard.setDiscard({},2,17)==-EINVAL);IP::Address mapped{};mapped[10]=mapped[11]=255;C(discard.setDiscard(mapped,2,17)==-EINVAL);C(discard.setDiscard(address(1),UINT32_MAX,2)==-EINVAL);
 for(uint32_t first:{0u,2u,17u})for(uint32_t second:{0u,2u,17u}){
  C(discard.setDiscard(address(1),first,second)==0&&discard.compile(base,&out)==0);
  for(uint32_t iif:{0u,1u,2u,17u,2147483647u})for(bool dns:{false,true})for(bool output:{false,true})for(unsigned version:{0u,4u,6u})for(unsigned n:{1u,2u}){
   auto dst=address(n),configured=address(1);assert(evaluate(out,10001,iif,dns,output,dst,version)==bool(g24OracleDiscard(configured.data(),dst.data(),first,second,iif,output,version)));++comparisons;
  }
 }
 C(discard.clearDiscard(address(1))==0&&discard.compile(base,&out)==0&&out==base);for(unsigned i=1;i<=100;i++)assert(discard.setDiscard(address(i),2,17)==0);C(discard.setDiscard(address(101),2,17)==-E2BIG);C(discard.setDiscard(address(1),3,4)==0);C(discard.clearDiscard(address(50))==0&&discard.setDiscard(address(101),2,17)==0);
 IP large;for(unsigned i=0;i<20000;i++)assert(large.setIif(10000+i,17)==0);C(large.setIif(30000,17)==-E2BIG&&large.setIif(10000,17)==0);C((large.compile(base,&out)==0&&out[9].rules.size()==13&&out[9].rules[11].uid==std::optional<ChainIO::UidRange>{{10000,29999}}));
 // Typed read/write/rollback and exact root activation in both families.
 IP full;C(full.setDiscard(address(1),2,17)==0&&full.setIif(10001,17)==0&&full.setLockdown(10002,true)==0);RootImage desired;C(full.compile(base,&desired)==0);C(ChainIO::validateImage(desired,ChainIO::Table::Socket)==0&&ChainIO::validateImage(desired,ChainIO::Table::Filter)==-EINVAL);
 initRoots();features=1023;{NetpolicyLease lease;Tables k;k.seed(base);SocketRoots roots(k,lease);ChainIO writer(k,ChainIO::Table::Socket);C(lease.start()==0);for(auto family:{V4,V6}){C(writer.replace(family,desired)==0);RootImage actual;C(writer.read(family,allNames(),&actual)==0&&actual==desired);}C(roots.activate(desired)==0&&roots.verify(desired)==0&&held&&k.active());}
 for(int feature:{0,255,256,511,512,767}){initRoots();features=feature;NetpolicyLease lease;Tables k;k.seed(desired);SocketRoots roots(k,lease);C(lease.start()==0);C(roots.activate(desired)==-EOPNOTSUPP&&files.empty()&&held&&k.calls==0);}
 // Both primitive bits are sufficient; no fake global-readiness bit is used.
 initRoots();features=768;{NetpolicyLease lease;Tables k;k.seed(desired);SocketRoots roots(k,lease);C(lease.start()==0&&roots.activate(desired)==0&&held);}
 for(int fault=0;fault<6;fault++){
  auto bad=desired;auto&r=bad[9].rules[11];if(fault==0)r.ingressDiscard->daddr={};if(fault==1)r.verdict=ChainIO::Verdict::Return;if(fault==2)r.ingressIfIndex=17;if(fault==3)r.ingressDiscard->allowedIfIndex[0]=UINT32_MAX;if(fault==4)std::swap(bad[9].rules[11],bad[9].rules[12]);if(fault==5)bad[10].rules.insert(bad[10].rules.end()-1,bad[9].rules[11]);
  initRoots();features=1023;NetpolicyLease lease;Tables k;SocketRoots roots(k,lease);C(lease.start()==0);C(roots.activate(bad)==-EINVAL&&!files.empty()&&k.calls==0&&held);
 }
 C(files.empty()&&held);printf("passed_cases=%u oracle_comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.cpp').write_text(code);names=['Gta3xlwifiNetpolicyLease','Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiSocketRoots','Gta3xlwifiIngressPolicy'];sources=[S/(n+'.cpp') for n in names]
cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),str(O/'oracle.o'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.search(r'passed_cases=(\d+) oracle_comparisons=(\d+)\n$',x.stdout);assert m and int(m[2])==1800
paths=[Path(__file__),helper,prior,oracle,O/'oracle.c',O/'test.cpp',*sources,*[p.with_suffix('.h') for p in sources],*[p for p in (S/'linux/netfilter').glob('*.h')]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':x.stderr,'actual_A17_comparisons':int(m[2]),'inputs_sha256':{str(p):sha(p) for p in paths},'oracle_reference_inputs_sha256':r['inputs_sha256'],'command':cmd,'oracle_command':cc,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
