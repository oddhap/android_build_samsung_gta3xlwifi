#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare typed ordinary dispatch with actual A17 bpf_owner_match.

Actual reference owner/skip/bit predicates; maps, packet metadata and the interface
index are fixtures. VPN/IIF memberships and ingress-discard map are absent in
this ordinary-only scope. No actual packets, hooks or readiness are established.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
header=A/'packages/modules/Connectivity/bpf/progs/netd.h';reference=header.with_name('netd.c');h=header.read_text();r=reference.read_text();enum=re.search(r'enum UidOwnerMatchType : uint32_t \{.*?\n\};',h,re.S).group();defines=h[h.index('#define DROP_IF_SET '):h.index('#define FIREWALL_DROP_IF_SET ')]
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
#include "Gta3xlwifiOrdinaryDispatch.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
using namespace android::net::gta3xlwifi;
using C=CheckedUidChains;using Image=UidChainProgram::Image;
namespace Oracle{
#define function static
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
#define IPPROTO_ESP 50
#define IPPROTO_TCP 6
#define TCP_FLAG8_RST 4
#define TCP_FLAG8_FIN 1
#define API_IS_AT_LEAST(lvl,api) ((lvl).value>=1)
using BpfConfig=uint32_t;
struct SkbIpPacketData{uint8_t ip_version,ip_proto,tcp_flags;};
struct egress_bool{bool egress;};struct kver_uint{unsigned value;};struct sdk_level_uint{unsigned value;};
struct __sk_buff{uint32_t ifindex;};struct UidOwnerValue{uint32_t iif,rule;};
static constexpr unsigned UID_RULES_CONFIGURATION_KEY=0;
static constexpr int PASS=1,DROP=0,DROP_UNLESS_DNS=2;
static BpfConfig configuration=0;static UidOwnerValue entry;
static BpfConfig getConfig(unsigned key){assert(key==0);return configuration;}
static UidOwnerValue* bpf_uid_owner_map_lookup_elem(const uint32_t* uid){return *uid==10001||*uid==110001||*uid==INT_MAX?&entry:nullptr;}
static bool ingress_should_discard(const SkbIpPacketData*,__sk_buff*,kver_uint){return false;}
'''+enum+'\n'+defines+'\n'+m.extract(h,'isBlockedByUidRules')+'\n'+m.extract(h,'is_system_uid')+'\n'+m.extract(r,'skip_owner_match')+'\n'+m.extract(r,'bpf_owner_match')+r'''
}
unsigned cases=0,comparisons=0;
#define T(x) do{assert(x);++cases;}while(0)
struct Packet{uint32_t uid,index;bool egress;uint8_t protocol,flags;};
bool rejected(const Image& image,const C::Chain& chain,const Packet& p,unsigned depth=0){
 assert(depth<2);
 for(const auto& rule:chain.rules){
  uint32_t uid=p.uid;
  if(rule.selector==C::Selector::RawAppId)uid=(uid==65534?0:uid)%100000;
  else if(rule.selector==C::Selector::OwnerSkip){
   if(!(p.protocol==50||(p.protocol==6&&(p.flags&(p.egress?4:5)))))continue;
  }else if(rule.selector==C::Selector::NonLoopback){if(p.index==1)continue;}
  else if(rule.uid)assert(rule.selector==C::Selector::RawUid);
  if(rule.uid&&(uid<rule.uid->first||uid>rule.uid->last))continue;
  if(rule.verdict==C::Verdict::Return)return false;
  if(rule.verdict==C::Verdict::Drop)return true;
  assert(rule.verdict==C::Verdict::UidCall&&rule.targetUidChain>=1&&rule.targetUidChain<=9);
  if(rejected(image,image.at(rule.targetUidChain-1),p,depth+1))return true;
 }
 return false;
}
int main(){
 T(OrdinaryDispatch::append(nullptr)==-EINVAL);Image absent,output;T(OrdinaryDispatch::append(&absent)==-EINVAL&&absent.empty());
 UidPolicy empty;T(UidChainProgram::ordinary(empty,&output)==0);T(OrdinaryDispatch::append(&output)==0&&output.size()==11);
 auto unchanged=output;T(OrdinaryDispatch::append(&output)==-EINVAL&&output==unchanged);
 for(size_t i=9;i<11;i++){
  T(output[i].rules.size()==12);T(output[i].rules[0].selector==C::Selector::RawAppId);
  T(output[i].rules[1].selector==C::Selector::OwnerSkip);
  T(output[i].rules[7].targetUidChain==6&&output[i].rules[7].selector==C::Selector::NonLoopback);
 }
 const uint32_t bits[]={Oracle::DOZABLE_MATCH,Oracle::STANDBY_MATCH,Oracle::POWERSAVE_MATCH,Oracle::RESTRICTED_MATCH,Oracle::LOW_POWER_STANDBY_MATCH,Oracle::BACKGROUND_MATCH,Oracle::OEM_DENY_1_MATCH,Oracle::OEM_DENY_2_MATCH,Oracle::OEM_DENY_3_MATCH};
 const Packet contexts[]={{0,2,true,17,0},{0,1,true,17,0},{0,1,false,17,0},{0,2,false,6,1},{0,2,true,6,1},{0,2,true,6,4},{0,2,false,50,0},{0,2,true,6,16}};
 for(unsigned enabled=0;enabled<512;enabled++)for(unsigned membership=0;membership<512;membership++){
  UidPolicy policy;Oracle::configuration=0;Oracle::entry={0,0};
  for(const auto& chain:UidPolicy::chains())if(!chain.metered){unsigned n=chain.id-1;assert(policy.setChainEnabled(chain.id,enabled&(1u<<n))==0);if(enabled&(1u<<n))Oracle::configuration|=bits[n];
   if(membership&(1u<<n)){Oracle::entry.rule|=bits[n];assert(policy.replaceUidChain(chain.id,{10001,110001,INT_MAX})==0);}}
  assert(UidChainProgram::ordinary(policy,&output)==0&&OrdinaryDispatch::append(&output)==0);
  for(uint32_t uid:{10001u,110001u,static_cast<uint32_t>(INT_MAX),20001u,100001u,65534u})for(Packet packet:contexts){
   packet.uid=uid;Oracle::SkbIpPacketData parsed{4,packet.protocol,packet.flags};Oracle::__sk_buff skb{packet.index};
   int expected=Oracle::bpf_owner_match(&parsed,&skb,uid==65534?0:uid,{packet.egress},{515},{1});
   bool actual=rejected(output,output.at(packet.egress?10:9),packet);
   assert(actual==(expected==Oracle::DROP));++comparisons;
  }
 }
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.cpp').write_text(code);sources=[S/(n+'.cpp') for n in ['Gta3xlwifiUidPolicy','Gta3xlwifiCheckedUidChains','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch']]
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-O2','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=180);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',x.stdout);assert match and int(match[1])>=10 and int(match[2])==12582912
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,header,reference,O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[x.with_suffix('.h') for x in sources]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_android17_ordinary_owner_comparisons':int(match[2]),'stderr':x.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual A17 ordinary owner vs typed dispatch, fatal UBSan')
