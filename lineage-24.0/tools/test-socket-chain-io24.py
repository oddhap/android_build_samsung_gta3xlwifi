#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real checked UID chain I/O with explicit private g24sock table and strict grammar.

Original84 filter regressions remain. Kernel command effects are scripted; no
packet hooks, root bootstrap, full transaction or readiness is provided here.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-checked-uid-chains24.py');subprocess.run(['python3',str(helper),'--source',str(S),'--output',str(O/'filter-regression')],check=True)
code=(O/'filter-regression/test.cpp').read_text().split('int main(){',1)[0]
code+=r'''
#include "Gta3xlwifiOrdinaryDispatch.h"
using namespace android::net::gta3xlwifi;
std::vector<C::Chain> socketImage(unsigned uid){return {{"g24_uid_1",{{C::UidRange{uid,uid},V::Return,C::Selector::RawUid},{std::nullopt,V::Drop}}}};}
const std::string sq="*g24sock\n-S g24_uid_1\nCOMMIT\n";
const std::string so="-N g24_uid_1\n-A g24_uid_1 -m gta3xlwifi_raw_uid --raw_uid 10001:10001 -j RETURN\n-A g24_uid_1 -j DROP\n";
const std::string sn="-N g24_uid_1\n-A g24_uid_1 -m gta3xlwifi_raw_uid --raw_uid 110001:110001 -j RETURN\n-A g24_uid_1 -j DROP\n";
const std::string sow="*g24sock\n:g24_uid_1 -\n-A g24_uid_1 -m gta3xlwifi_raw_uid --raw_uid 10001:10001 -j RETURN\n-A g24_uid_1 -j DROP\nCOMMIT\n";
const std::string snw="*g24sock\n:g24_uid_1 -\n-A g24_uid_1 -m gta3xlwifi_raw_uid --raw_uid 110001:110001 -j RETURN\n-A g24_uid_1 -j DROP\nCOMMIT\n";
int main(){unsigned cases=0;auto check=[&](bool value){assert(value);++cases;};
 for(auto family:{V4,V6}){
  Kernel k;k.family=family;C writer(k,C::Table::Socket);std::vector<C::Chain> out=socketImage(777);
  k.steps={{sq,so}};check(writer.read(family,{"g24_uid_1"},&out)==0&&out==socketImage(10001));k.done();
  k.steps={{sq,so}};check(writer.replace(family,socketImage(10001))==0);k.done();
  k.steps={{sq,so},{snw,""},{sq,sn}};check(writer.replace(family,socketImage(110001))==0);k.done();
  for(auto bad:{std::string("bad"),so}){k.steps={{sq,so},{snw,""},{sq,bad},{sow,""},{sq,so}};check(writer.replace(family,socketImage(110001))==-EREMOTEIO);k.done();}
  k.steps={{sq,so},{snw,"",-1},{sow,""},{sq,so}};check(writer.replace(family,socketImage(110001))==-EREMOTEIO);k.done();
  k.steps={{sq,so},{snw,"",-1},{sow,"",-1}};check(writer.replace(family,socketImage(110001))==-EUCLEAN);k.done();
  k.steps={{sq,so},{snw,"",-1},{sow,""},{sq,sn}};check(writer.replace(family,socketImage(110001))==-EUCLEAN);k.done();
  for(auto bad:std::vector<std::string>{"-N g24_uid_1\n-A g24_uid_1 -j REJECT\n","-N g24_uid_1\n-A g24_uid_1 -m owner --uid-owner 10001 -j RETURN\n","-N g24_uid_1\n-A g24_uid_1 -m gta3xlwifi_appid --appid 10001:10001 -j RETURN\n","-N g24_uid_1\n-A g24_uid_1 -j NFQUEUE\n","-P INPUT ACCEPT\n",so+"-N foreign\n"}){out=socketImage(777);k.steps={{sq,bad}};check(writer.read(family,{"g24_uid_1"},&out)==-EPROTO&&out==socketImage(777));k.done();}
  for(const auto& name:{"INPUT","g24_data_saver","g24_meter_deny","g24_uid_0","g24_uid_10","g24_uid_1x","g24_uid"}){unsigned before=k.calls;check(writer.read(family,{name},&out)==-EINVAL&&k.calls==before);}
  for(auto selector:{C::Selector::Owner,C::Selector::LookupAppId}){auto bad=socketImage(10001);bad[0].rules[0].selector=selector;unsigned before=k.calls;check(writer.replace(family,bad)==-EINVAL&&k.calls==before);}
  auto bad=socketImage(10001);bad[0].rules[1].verdict=V::Reject;check(writer.replace(family,bad)==-EINVAL);bad=socketImage(10001);bad[0].name="g24_data_saver";check(writer.replace(family,bad)==-EINVAL);
  C invalid(k,static_cast<C::Table>(77));unsigned before=k.calls;check(invalid.read(family,{"g24_uid_1"},&out)==-EINVAL&&k.calls==before);check(invalid.replace(family,socketImage(10001))==-EINVAL&&k.calls==before);k.done();
 }
 UidPolicy policy;check(policy.setChainEnabled(1,true)==0&&policy.setUidRule(1,10001,UidPolicy::Allow)==0);UidChainProgram::Image full;check(UidChainProgram::ordinary(policy,&full)==0&&OrdinaryDispatch::append(&full)==0&&full.size()==11);check(C::validateImage(full,C::Table::Socket)==0);full.push_back({"g24_meter_deny",{{std::nullopt,V::Drop}}});check(C::validateImage(full,C::Table::Socket)==-EINVAL);check(C::validateImage(full,C::Table::Filter)==0);
 std::cout<<"passed_cases="<<cases<<"\n";
}
''';(O/'test.cpp').write_text(code);shutil.copyfile(O/'filter-regression/IptablesRestoreController.h',O/'IptablesRestoreController.h')
names=['Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch'];sources=[S/(n+'.cpp') for n in names];cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=30,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',r.stdout);assert m and int(m[1])>=50
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,*sources,*[p.with_suffix('.h') for p in sources],O/'test.cpp'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':r.stderr,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; actual private-table checked I/O, fatal UBSan fixtures')
