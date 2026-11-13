#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real four-state two-table policy projection with shared lease and fault I/O.

Compiles actual owner/lease/state/compiler/root code; syscall/table effects are
fixtures. Failure at each ioctl/firewall point, publication and hard post-SET
firewall cutoff are exercised. Not real kernel networking or global readiness.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','roots-host','transport-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.roots_host.resolve();T=a.transport_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for base in [R,T]:
 report=json.loads((base/'report.json').read_text());assert report['passed'] and sha(base/'test.cpp')==report['inputs_sha256'][str(base/'test.cpp')]
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
code=(T/'test.cpp').read_text().split('int main(){',1)[0]
code='static bool firewallAllowed=true;\n'+code
code=code.replace('extern "C" int __wrap_ioctl(', 'extern "C" int imageIoctl(',1)
code=code.replace('held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;', 'if(cmd==GTA3XLWIFI_NETPOLICY_HOLD){firewallAllowed=true;}held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;')
code=code.replace('++setCalls;', '++setCalls;firewallAllowed=false;',1).replace('assert(held);++lnaSets;', 'assert(held);++lnaSets;firewallAllowed=false;',1)
assert 'firewallAllowed=false;' in code
# Outermost wrapper shares one fault clock across ioctl and both firewall tables.
code+=r'''
static unsigned ioCount,ioFault;static bool ioAfter;
static bool point(){return ++ioCount==ioFault;}
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);bool bad=point();if(bad&&!ioAfter){errno=EIO;return -1;}if(cmd==GTA3XLWIFI_LOOPBACK_GET_EVENTS){errno=ENOTTY;return -1;}int result=imageIoctl(fd,cmd,arg);if(bad){errno=EIO;return -1;}return result;}
'''
code='#include <linux/netfilter/gta3xlwifi_loopback.h>\n'+code
root=(R/'test.cpp').read_text();start=root.index('#include "Gta3xlwifiSocketRoots.h"');end=root.index('int main(){',start);code+=root[start:end]
# The metered fixture accepts exact encoded chain replacement, too.
needle='else if(line.rfind("-A ",0)==0){auto n=line.substr';assert needle in code
code=code.replace(needle,'else if(line.front()==\':\'){auto n=line.substr(1,line.find(\' \')-1);assert(t.chains.count(n));t.chains[n].clear();}'+needle,1)
code+=r'''
#include "Gta3xlwifiSocketPolicyProjection.h"
#include <thread>
using P=SocketPolicyProjection;
struct Combined:IptablesRestoreInterface{
 Tables socket;MK filter;unsigned calls=0;bool denyControl=false;
 std::array<std::map<std::string,std::vector<std::string>>,2> hooks;
 Combined(){for(unsigned f=0;f<2;f++){filter.tables[f].chains["bw_FORWARD"]={};for(auto n:{"INPUT","FORWARD","OUTPUT"})hooks[f][n]={"-A "+std::string(n)+" -m gta3xlwifi_guard -j DROP"};}}
 int execute(IptablesTarget family,const std::string&cmd,std::string*out)override{
  assert(firewallAllowed);++calls;bool bad=point();if(bad&&!ioAfter)return -1;
  if(denyControl)for(auto&e:kernelImage)if(e.uid==0&&(e.permissions&4))return -1;
  int result=0;
  if(cmd.rfind("*g24sock\n",0)==0)result=socket.execute(family,cmd,out);
  else{
   auto f=family==V4?0:1;bool handled=false;
   for(unsigned i=0;i<3;i++){std::string n=i==0?"INPUT":i==1?"FORWARD":"OUTPUT";
    if(cmd=="*filter\n-S "+n+"\nCOMMIT\n"){assert(out);*out="-P "+n+" "+filter.tables[f].builtin[i]+"\n";for(auto&r:hooks[f][n])*out+=r+"\n";handled=true;}
   }
   if(!handled&&cmd.rfind("*filter\n-I ",0)==0){assert(!out);std::istringstream in(cmd);std::string line;std::getline(in,line);while(std::getline(in,line)&&line!="COMMIT"){auto n=line.substr(3,line.find(' ',3)-3);hooks[f][n].insert(hooks[f][n].begin(),"-A "+n+" -m gta3xlwifi_guard -j DROP");}handled=true;}
   if(!handled){result=filter.execute(family,cmd,out);if(out&&cmd=="*filter\n-S\nCOMMIT\n")for(const auto&[n,rules]:hooks[f])for(const auto&rule:rules)*out+=rule+"\n";}
  }
  return bad?-1:result;
 }
};
void resetProjection(){resetLna();features=1023;ioCount=ioFault=0;ioAfter=false;firewallAllowed=true;}
P::State desired(unsigned marker=10001){P::State s;assert(s.policy.setChainEnabled(1,true)==0&&s.policy.setUidRule(1,marker,UidPolicy::Allow)==0);s.policy.setDataSaver(true);assert(s.ingress.setIif(marker,17)==0&&s.ingress.setLockdown(marker,true)==0);assert(s.permissions.set(marker,65)==0);NetpolicyLease::LocalNetworkEntry h={64,{},true};memcpy(h.key.data(),&marker,4);assert(s.local.set(LocalNetworkState::Table::Host,h)==0);return s;}
void checkState(P&p,unsigned marker,uint64_t generation){P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==0&&g==generation);int32_t rule=0;uint32_t perm=0;C(out.policy.getUidRule(1,marker,&rule)==0&&rule==UidPolicy::Allow&&out.permissions.get(marker,&perm)==0&&perm==65);std::vector<int32_t> u;C(out.ingress.ownerUids(&u)==0&&u==std::vector<int32_t>{int32_t(marker)});std::vector<NetpolicyLease::LocalNetworkEntry> n,h;C(out.local.snapshot(&n,&h)==0&&h.size()==1);}
int main(){
 unsigned startPoints=0,replacePoints=0,committedPoints=0;auto a=desired(),b=desired(110001);
 resetProjection();{Combined k;P p(k);P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.replace(a,0)==-ENOTCONN&&ioCount==0);C(p.start()==0&&held&&opens==1);startPoints=ioCount;C(p.snapshot(&out,&g)==-EAGAIN);ioCount=0;C(p.replace(a,0)==0&&!held&&lnaSets==1&&setCalls==1&&opens==1);replacePoints=ioCount;checkState(p,10001,1);auto before=ioCount;C(p.replace(b,0)==-ESTALE&&ioCount==before);before=ioCount;C(p.replace(b,1)==0&&!held&&lnaRevision==2&&kernelRevision==2);committedPoints=ioCount-before;checkState(p,110001,2);C(p.removeUid(110001)==0&&!held);C(p.snapshot(&out,&g)==0&&g==3);uint32_t permissions=99;std::vector<int32_t> owners;std::vector<NetpolicyLease::LocalNetworkEntry> n,h;C(out.permissions.get(110001,&permissions)==0&&permissions==0&&out.ingress.ownerUids(&owners)==0&&owners.empty()&&out.local.snapshot(&n,&h)==0&&h.empty());}
 for(unsigned missing=0;missing<10;missing++){resetProjection();features=1023^(1u<<missing);Combined k;P p(k);C(p.start()==-EOPNOTSUPP&&held&&files.empty()&&k.calls==0);}
 for(bool after:{false,true})for(unsigned point=1;point<=startPoints;point++){resetProjection();Combined k;P p(k);ioFault=point;ioAfter=after;C(p.start()<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 for(bool after:{false,true})for(unsigned point=1;point<=replacePoints;point++){resetProjection();Combined k;P p(k);C(p.start()==0);ioCount=0;ioFault=point;ioAfter=after;C(p.replace(a,0)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.replace(b,0)==-ENOTCONN);}
 // The same quarantine guarantee holds AFTER a previous state was published.
 for(unsigned point:{1u,10u,committedPoints/2,committedPoints-2,committedPoints}){resetProjection();Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);ioCount=0;ioFault=point;ioAfter=true;C(p.replace(b,1)<0&&held&&files.empty());P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==-EAGAIN);}
 resetProjection();{Combined k;for(auto&f:k.hooks)for(auto&[n,r]:f)r.clear();P p(k);C(p.start(P::HookMode::InstallMissing)==0&&held);C(p.replace(a,0)==0&&!held);}
 // A shared-map overflow across otherwise valid independent components is pure
 // failure, not a partial policy change or a fabricated successful projection.
 resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);auto huge=a;for(int uid=10000;uid<30000;uid++)assert(huge.policy.setUidRule(11,uid,UidPolicy::Deny)==0);assert(huge.ingress.setIif(40000,0)==0);auto before=ioCount;C(p.replace(huge,1)==-E2BIG&&ioCount==before&&!held);checkState(p,10001,1);}
 resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);std::thread x([&]{assert(p.setIif(20001,18)==0);}),y([&]{assert(p.setUidPermission(20002,4)==0);}),z([&]{assert(p.setLockdown(20003,true)==0);});x.join();y.join();z.join();P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==0&&g==4&&!held&&opens==1);std::vector<int32_t> owners;C(out.ingress.ownerUids(&owners)==0&&owners==std::vector<int32_t>({10001,20001,20003}));uint32_t perm=0;C(out.permissions.get(20002,&perm)==0&&perm==4);}
 // Preserve the genuine NoInternet-root control corner; do not auto-clear it.
 resetProjection();{Combined k;k.denyControl=true;P p(k);auto root=a;assert(root.permissions.set(0,4)==0);C(p.start()==0&&p.replace(root,0)==0&&!held);C(p.setDataSaver(false)<0&&held&&files.empty()&&kernelImage.front().uid==0&&kernelImage.front().permissions==4);}
 resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);NetpolicyLease::LoopbackBatch batch;C(p.readLoopbackEvents(nullptr)==-EINVAL);C(p.readLoopbackEvents(&batch)==-ENOTTY&&held&&files.empty());P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==-EAGAIN);}
 C(files.empty()&&held);printf("passed_cases=%u start_fault_points=%u replace_fault_points=%u\n",cases,startPoints,replacePoints);
}
'''
iface_header=S/'linux/netfilter/gta3xlwifi_iface_stats.h'
if iface_header.exists():
 code=code.replace(' C(files.empty()&&held);printf(', ' resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);NetpolicyLease::IfaceSnapshot counters;C(p.readIfaceStats(nullptr)==-EINVAL);C(p.readIfaceStats(&counters)==-EOPNOTSUPP&&held&&files.empty());P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==-EAGAIN); }\n C(files.empty()&&held);printf(',1)
(O/'test.cpp').write_text(code);names=['Gta3xlwifiNetpolicyLease','Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiSocketRoots','Gta3xlwifiIngressPolicy','Gta3xlwifiMeteredChainProgram','Gta3xlwifiMeteredRoots','Gta3xlwifiUidPermissionState','Gta3xlwifiLocalNetworkState','Gta3xlwifiSocketPolicyProjection'];sources=[S/(n+'.cpp') for n in names]
cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=120,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+) start_fault_points=(\d+) replace_fault_points=(\d+)\n',x.stdout);assert m and int(m[1])>300
paths=[Path(__file__),R/'report.json',R/'test.cpp',T/'report.json',T/'test.cpp',O/'test.cpp',S/'projection-guards.inc',*sources,*[p.with_suffix('.h') for p in sources],*[p for p in (S/'linux/netfilter').glob('*.h')]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'start_fault_points':int(m[2]),'replace_fault_points':int(m[3]),'stderr':x.stderr,'hard_no_firewall_after_first_image_set':True,'one_lease_four_state_publication':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
