#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real metered parent bootstrap/activation, fault fixtures and A17 graph oracle.

Uses actual lease, checked encoder, compiler and new parent C++. Syscalls and
iptables effects are models. Critical exceptions are bound to actual A17 factory,
ICMP name/code table and -S format source. No real rules/readiness are installed.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();H=a.reference_host.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();prior=H/'report.json';r=json.loads(prior.read_text());assert r['passed'] and r['actual_A17_comparisons']==1800
fixture=H/'test.cpp';assert sha(fixture)==r['inputs_sha256'][str(fixture)]
for path,h in r['inputs_sha256'].items():
 if '/ingress-chain24-20261113-01/' in path:
  name=path.split('/ingress-chain24-20261113-01/',1)[1];assert sha(S/name)==h,name
shutil.copyfile(H/'IptablesRestoreController.h',O/'IptablesRestoreController.h')
f=A/'system/netd/server/FirewallController.cpp';bw=A/'system/netd/server/BandwidthController.cpp';icmp=A/'external/iptables/extensions/libxt_icmp.h';save=A/'external/iptables/extensions/libip6t_icmp6.c';shared=A/'external/iptables/iptables/xshared.c';xt=A/'external/iptables/libxtables/xtables.c'
ft=f.read_text();block=ft[ft.index('const char* const FirewallController::ICMPV6_TYPES[]'):];block=block[:block.index('};')];names=re.findall(r'"([a-z-]+)"',block);assert len(names)==6
codes=icmp.read_text().split('icmpv6_codes[]',1)[1].split('igmp_types[]',1)[0];numbers=[]
for name in names:
 m=re.search(r'\{\s*"'+name+r'",\s*(\d+),\s*0,\s*0xFF\s*\}',codes);assert m; numbers.append(int(m[1]))
assert numbers==[2,133,134,135,136,137]
critical_names=names.copy()
assert 'if (target == V6)' in ft and '"-A %s -p icmpv6 --icmpv6-type %s -j RETURN\\n"' in ft
assert 'printf(" --icmpv6-type %u", icmpv6->type);' in save.read_text() and 'proto_to_name(proto, true)' in shared.read_text()
assert xt.read_text().index('{"ipv6-icmp", IPPROTO_ICMPV6}')<xt.read_text().index('{"icmpv6",    IPPROTO_ICMPV6}')
assert '"-A bw_costly_shared -j bw_penalty_box"' in bw.read_text() and 'StringPrintf("-A %s -j bw_penalty_box", chain.c_str())' in bw.read_text()
code=fixture.read_text().split('int main(){',1)[0]
code+=r'''
#include "Gta3xlwifiMeteredRoots.h"
#include "Gta3xlwifiMeteredChainProgram.h"
using MR=MeteredRoots;
const std::vector<std::string> meterNames={"g24_meter_deny","g24_meter_allow","g24_data_saver"};
RootImage metered(bool saver=false,bool happy=false,bool deny=false,uint32_t uid=10001){UidPolicy p;p.setDataSaver(saver);if(happy)assert(p.setUidRule(10,uid,UidPolicy::Allow)==0);if(deny)assert(p.setUidRule(11,uid,UidPolicy::Deny)==0);RootImage v;assert(MeteredChainProgram::compile(p,&v)==0);return v;}
struct MK:IptablesRestoreInterface{
 struct T{std::map<std::string,std::vector<std::string>> chains;std::array<std::string,3> builtin={"ACCEPT","DROP","ACCEPT"};};std::array<T,2> tables;
 unsigned calls=0,writes=0,failAt=0,malformAt=0,foreignAt=0;bool after=false;std::string malformed;
 MK(){for(auto&t:tables){for(const auto&n:{"bw_penalty_box","bw_happy_box","bw_data_saver","bw_INPUT","bw_OUTPUT","bw_costly_test","foreign"})t.chains[n]={};t.chains["bw_data_saver"]={"-A bw_data_saver -j RETURN"};t.chains["bw_costly_test"]={"-A bw_costly_test -m quota2 --name quota_test --quota 100000 -j REJECT","-A bw_costly_test -j bw_penalty_box"};t.chains["bw_INPUT"]={"-A bw_INPUT -i wlan0 -j bw_costly_test"};t.chains["bw_OUTPUT"]={"-A bw_OUTPUT -o wlan0 -j bw_costly_test"};}}
 void seed(const RootImage&v){for(auto&t:tables)for(const auto&c:v){auto&dst=t.chains[c.name];for(const auto&r:c.rules){std::string line="-A "+c.name;if(r.uid){line+=r.selector==ChainIO::Selector::RawAppId?" -m gta3xlwifi_raw_appid --raw_appid ":" -m gta3xlwifi_raw_uid --raw_uid ";line+=std::to_string(r.uid->first)+":"+std::to_string(r.uid->last);}if(r.verdict==ChainIO::Verdict::DataSaverGoto)line+=" -g g24_data_saver";else line+=r.verdict==ChainIO::Verdict::Reject?" -j REJECT":" -j RETURN";dst.push_back(line);}}}
 std::string list(const T&t,IptablesTarget family,const std::string&n){assert(t.chains.count(n));std::string out="-N "+n+"\n";for(auto line:t.chains.at(n)){if(line.ends_with(" -j REJECT"))line+=family==V4?" --reject-with icmp-port-unreachable":" --reject-with icmp6-port-unreachable";out+=line+"\n";}return out;}
 int execute(IptablesTarget family,const std::string&command,std::string*output)override{
  assert((family==V4||family==V6)&&held&&!files.empty());++calls;if(calls==failAt&&!after)return -1;auto&t=tables[family==V4?0:1];std::istringstream in(command);std::string line,text;assert(std::getline(in,line)&&line=="*filter");bool write=false;
  while(std::getline(in,line)){if(line=="COMMIT")break;if(line=="-S"){assert(output);unsigned i=0;for(auto n:{"INPUT","FORWARD","OUTPUT"})text+="-P "+std::string(n)+" "+t.builtin[i++]+"\n";for(auto&[n,r]:t.chains)text+="-N "+n+"\n";for(auto&[n,r]:t.chains){auto s=list(t,family,n);text+=s.substr(s.find('\n')+1);}continue;}
   if(line.rfind("-S ",0)==0){assert(output);text+=list(t,family,line.substr(3));continue;}
   assert(!output);write=true;if(line.rfind("-N ",0)==0){assert(t.chains.emplace(line.substr(3),std::vector<std::string>{}).second);}else if(line.rfind("-A ",0)==0){auto n=line.substr(3,line.find(' ',3)-3);assert(t.chains.count(n));t.chains[n].push_back(line);}else assert(false);
  }if(write)++writes;if(calls==foreignAt)t.chains["foreign"].push_back("-A foreign -j RETURN");if(output)*output=calls==malformAt?malformed:text;return calls==failAt?-1:0;
 }
};
// Execute actual newly emitted goto/call graph. Quota and raw UID/appId effects
// are fixtures; comparison below uses the independent original A17 rule order.
int runChain(const MK::T&t,const std::string&name,uint32_t uid,unsigned type,bool v6,bool quota,unsigned depth=0){assert(depth<12);for(const auto&line:t.chains.at(name)){
 std::istringstream in(line);std::vector<std::string>w;for(std::string x;in>>x;)w.push_back(x);bool match=true;
 for(size_t i=2;i+1<w.size();i++){if(w[i]=="--raw_uid"||w[i]=="--raw_appid"){auto r=w[++i];auto sep=r.find(':');unsigned a=std::stoul(r.substr(0,sep)),b=std::stoul(r.substr(sep+1));unsigned actual=uid;if(w[i-1]=="--raw_appid")actual=(uid==65534?0:uid)%100000;match&=a<=actual&&actual<=b;}else if(w[i]=="--icmpv6-type"){match&=v6&&type==std::stoul(w[++i]);}else if(w[i]=="--quota"){++i;match&=quota;}}
 if(!match){continue;}
 auto target=w.back();bool go=w[w.size()-2]=="-g";if(target=="RETURN")return 0;if(target=="REJECT")return 1;int child=runChain(t,target,uid,type,v6,quota,depth+1);if(child||go)return child;
 }return 0;
}
int main(){unsigned prepareCalls=0,activateCalls=0,comparisons=0;auto desired=metered(true);
 initRoots();{NetpolicyLease l;MK k;MR roots(k,l);C(l.start()==0&&roots.prepare()==0&&held&&k.writes==2);prepareCalls=k.calls;C(roots.prepare()==0&&k.writes==2);k.seed(desired);auto foreign=k.tables[0].chains["bw_costly_test"];unsigned before=k.calls;C(roots.activate(desired)==0&&held&&k.writes==4);activateCalls=k.calls-before;C(roots.verify(desired)==0&&roots.verifyPrepared()==0);C(k.tables[0].chains["bw_costly_test"]==foreign&&k.tables[0].builtin[1]=="DROP");C(roots.activate(desired)==0&&k.writes==4);C(k.tables[1].chains["bw_happy_box"].size()==7);}
 for(bool committed:{false,true})for(unsigned point=1;point<=prepareCalls;point++){initRoots();NetpolicyLease l;MK k;MR roots(k,l);C(l.start()==0);k.failAt=point;k.after=committed;C(roots.prepare()<0&&held&&files.empty());k.failAt=0;C(l.start()==0&&roots.prepare()==0&&held);}
 for(bool committed:{false,true})for(unsigned point=1;point<=activateCalls;point++){initRoots();NetpolicyLease l;MK k;k.seed(desired);MR roots(k,l);C(l.start()==0);k.failAt=point;k.after=committed;C(roots.activate(desired)<0&&held&&files.empty());k.failAt=0;C(l.start()==0&&roots.activate(desired)==0&&held);}
 for(unsigned f=0;f<2;f++)for(unsigned fault=0;fault<7;fault++){initRoots();NetpolicyLease l;MK k;auto&t=k.tables[f];if(fault==0)t.chains["bw_penalty_box"]={"-A bw_penalty_box -m bpf --object-pinned /sys/fs/bpf/netd_shared/prog_netd_denylist_xtbpf -j REJECT"};if(fault==1)t.chains["bw_happy_box"]={"-A bw_happy_box -j bw_data_saver"};if(fault==2)t.chains["g24_owner_in"]={};if(fault==3)t.chains["foreign"]={"-A foreign -j g24_meter_allow"};if(fault==4)t.chains.erase("bw_penalty_box");if(fault==5)t.chains["g24_meter_deny"]={"-A g24_meter_deny -j RETURN"};if(fault==6)t.chains["bw_penalty_box"]={"-A bw_penalty_box -j bw_happy_box"};MR roots(k,l);C(l.start()==0&&roots.prepare()==-EPROTO&&held&&files.empty()&&k.writes==0);}
 initRoots();{NetpolicyLease l;MK k;k.foreignAt=4;MR roots(k,l);C(l.start()==0&&roots.prepare()==-ESTALE&&files.empty()&&held);}
 initRoots();{NetpolicyLease l;MK k;MR roots(k,l);C(l.start()==0&&l.release()==0);C(roots.prepare()==-EBUSY&&files.empty()&&held&&k.calls==0);}
 for(unsigned fault=0;fault<4;fault++){auto bad=desired;if(fault==0)bad.pop_back();if(fault==1)bad[0].rules.back().verdict=ChainIO::Verdict::Reject;if(fault==2)bad[1].rules.front().uid=ChainIO::UidRange{0,10000};if(fault==3)bad[2].rules.push_back(bad[2].rules.front());initRoots();NetpolicyLease l;MK k;MR roots(k,l);C(l.start()==0);C(roots.activate(bad)==-EINVAL&&k.calls==0&&!files.empty()&&held);}
 for(bool saver:{false,true})for(bool happy:{false,true})for(bool deny:{false,true})for(uint32_t uid:{0u,1000u,10001u,65534u,110001u}){
  auto v=metered(saver,happy,deny,uid);initRoots();NetpolicyLease l;MK k;k.seed(v);MR roots(k,l);assert(l.start()==0&&roots.activate(v)==0);
  for(bool v6:{false,true})for(unsigned type:{0u,2u,128u,133u,134u,135u,136u,137u})for(bool quota:{false,true}){auto&t=k.tables[v6?1:0];bool critical=v6&&(type==2||type==133||type==134||type==135||type==136||type==137);bool allow=uid==65534||uid%100000<10000||happy;bool original=quota||deny||(!allow&&saver&&!critical);assert(bool(runChain(t,"bw_costly_test",uid,type,v6,quota))==original);++comparisons;}
 }
 C(files.empty()&&held);printf("passed_cases=%u graph_comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.cpp').write_text(code);names=['Gta3xlwifiNetpolicyLease','Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiSocketRoots','Gta3xlwifiIngressPolicy','Gta3xlwifiMeteredChainProgram','Gta3xlwifiMeteredRoots'];sources=[S/(n+'.cpp') for n in names]
cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+) graph_comparisons=(\d+)\n',x.stdout);assert m and int(m[2])==1280
paths=[Path(__file__),prior,fixture,f,bw,icmp,save,shared,xt,O/'test.cpp',*sources,*[p.with_suffix('.h') for p in sources],*[p for p in (S/'linux/netfilter').glob('*.h')]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'graph_comparisons':int(m[2]),'stderr':x.stderr,'critical_a17_names':critical_names,'critical_numeric_types':numbers,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
