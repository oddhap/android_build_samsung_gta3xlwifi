#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check typed ordinary-UID chain programs against actual Android17 BPF bit logic.

Runs the actual policy/compiler/encoder with fatal UBSan and an independent
interpreter for its nine ordinary chains. No hook/packet dispatch, core bypass,
metered/VPN/LNA/network readiness or kernel execution is established.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
reference=A/'packages/modules/Connectivity/bpf/progs/netd.h';text=reference.read_text();enum=re.search(r'enum UidOwnerMatchType : uint32_t \{.*?\n\};',text,re.S).group();defines=text[text.index('#define DROP_IF_SET '):text.index('#define FIREWALL_DROP_IF_SET ')];function=m.extract(text,'isBlockedByUidRules')
(O/'IptablesRestoreController.h').write_text('''#pragma once
#include <string>
#ifndef EREMOTEIO
#define EREMOTEIO 121
#endif
#ifndef EUCLEAN
#define EUCLEAN 117
#endif
enum IptablesTarget{V4=1,V6=2,V4V6=3};
class IptablesRestoreInterface{public:virtual ~IptablesRestoreInterface()=default;virtual int execute(IptablesTarget,const std::string&,std::string*)=0;};
''');assert not (S/'IptablesRestoreController.h').exists()
code=r'''
#include "Gta3xlwifiUidChainProgram.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
using android::net::gta3xlwifi::UidPolicy;
using android::net::gta3xlwifi::UidChainProgram;
using C=android::net::gta3xlwifi::CheckedUidChains;
namespace Oracle{using BpfConfig=uint32_t;
'''+enum+'\n'+defines+'\n'+function+'}\n'+r'''
unsigned checks=0,comparisons=0;
#define T(x) do{assert(x);++checks;}while(0)
bool interpreted(const UidChainProgram::Image& image,uint32_t uid){
 for(const auto& chain:image){
  bool ended=false;
  for(const auto& rule:chain.rules){
   if(!rule.uid||(uid>=rule.uid->first&&uid<=rule.uid->last)){
    assert(rule.verdict==C::Verdict::Return||rule.verdict==C::Verdict::Drop);
    if(rule.verdict==C::Verdict::Drop)return true;
    ended=true;break;
   }
  }
  assert(ended);
 }
 return false;
}
int main(){
 const uint32_t expected[]={Oracle::DOZABLE_MATCH,Oracle::STANDBY_MATCH,Oracle::POWERSAVE_MATCH,Oracle::RESTRICTED_MATCH,Oracle::LOW_POWER_STANDBY_MATCH,Oracle::BACKGROUND_MATCH,Oracle::OEM_DENY_1_MATCH,Oracle::OEM_DENY_2_MATCH,Oracle::OEM_DENY_3_MATCH};
 unsigned index=0;for(const auto& type:UidPolicy::chains())if(!type.metered){T(type.match==expected[index]&&type.id==int(index+1));++index;}T(index==9);
 UidPolicy empty;std::vector<int32_t> members{123};T(empty.matchingUids(0,&members)==-EINVAL&&members==std::vector<int32_t>{123});T(empty.matchingUids(-1,&members)==-EINVAL&&members==std::vector<int32_t>{123});T(empty.matchingUids(13,&members)==-EINVAL);T(empty.matchingUids(1,nullptr)==-EINVAL);
 UidChainProgram::Image output{{"sentinel",{}}};auto sentinel=output;
 T(UidChainProgram::ordinary(empty,nullptr)==-EINVAL);T(UidChainProgram::ordinary(empty,&output)==0&&output.size()==9);
 for(const auto& chain:output)T(chain.rules.size()==1&&!chain.rules[0].uid&&chain.rules[0].verdict==C::Verdict::Return);
 UidPolicy ranges;T(ranges.setChainEnabled(1,true)==0);T(ranges.replaceUidChain(1,{10003,10001,10002,10002,INT_MAX-1,INT_MAX})==0);T(ranges.matchingUids(1,&members)==0&&(members==std::vector<int32_t>{10001,10002,10003,INT_MAX-1,INT_MAX}));T(UidChainProgram::ordinary(ranges,&output)==0);T(output[0].rules.size()==3);T((output[0].rules[0].uid==C::UidRange{10001,10003}));T((output[0].rules[1].uid==C::UidRange{INT_MAX-1,INT_MAX}));T(!output[0].rules[2].uid&&output[0].rules[2].verdict==C::Verdict::Drop);
 auto before=output;ranges.setDataSaver(true);for(const auto& type:UidPolicy::chains())if(type.metered){assert(ranges.setChainEnabled(type.id,true)==0);assert(ranges.setUidRule(type.id,20001,type.allowlist?UidPolicy::Allow:UidPolicy::Deny)==0);}T(UidChainProgram::ordinary(ranges,&output)==0&&output==before);
 UidPolicy huge;assert(huge.setChainEnabled(1,true)==0);for(int i=0;i<30000;i++)assert(huge.setUidRule(1,10000+2*i,UidPolicy::Allow)==0);output=sentinel;T(UidChainProgram::ordinary(huge,&output)==-E2BIG&&output==sentinel);
 for(unsigned enabled=0;enabled<512;enabled++){
  UidPolicy base;uint32_t config=0;index=0;
  for(const auto& type:UidPolicy::chains())if(!type.metered){assert(base.setChainEnabled(type.id,enabled&(1u<<index))==0);if(enabled&(1u<<index))config|=expected[index];++index;}
  for(unsigned membership=0;membership<512;membership++){
   UidPolicy p=base;uint32_t rules=0;index=0;
   for(const auto& type:UidPolicy::chains())if(!type.metered){if(membership&(1u<<index)){rules|=expected[index];for(int uid:{10001,110001,INT_MAX})assert(p.setUidRule(type.id,uid,type.allowlist?UidPolicy::Allow:UidPolicy::Deny)==0);}++index;}
   assert(UidChainProgram::ordinary(p,&output)==0&&output.size()==9);
   for(int uid:{10001,110001,INT_MAX,20001}){bool expectedBlocked=Oracle::isBlockedByUidRules(config,uid==20001?0:rules);assert(interpreted(output,uid)==expectedBlocked);++comparisons;}
  }
 }
 printf("passed_cases=%u comparisons=%u\n",checks,comparisons);
}
'''
(O/'test.cpp').write_text(code);sources=[S/n for n in ['Gta3xlwifiUidPolicy.cpp','Gta3xlwifiCheckedUidChains.cpp','Gta3xlwifiUidChainProgram.cpp']]
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=180);(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',r.stdout);assert match and int(match[1])>=30 and int(match[2])==1048576
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,reference,O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[S/n for n in ['Gta3xlwifiUidPolicy.h','Gta3xlwifiCheckedUidChains.h','Gta3xlwifiUidChainProgram.h']]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_android17_bit_predicate_comparisons':int(match[2]),'stderr':r.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; actual policy/compiler/encoder vs Android17 predicate, fatal UBSan')
