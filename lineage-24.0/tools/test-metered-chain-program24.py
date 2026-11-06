#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test isolated metered programs and typed checked I/O against A17 xtbpf predicates.

Actual compiler, policy, encoder/parser and extracted A17 expressions. Map/socket
UIDs and IptablesRestoreInterface are fixtures. No packets, hooks, kernel rules,
startup/Java/DNS integration or network readiness are established.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
reference=A/'packages/modules/Connectivity/bpf/progs/netd.c';header=A/'packages/modules/Connectivity/bpf/progs/netd.h';aids=A/'system/core/libcutils/include/private/android_filesystem_config.h'
assert re.search(r'#define AID_USER_OFFSET\s+100000\b',aids.read_text()) and re.search(r'#define AID_APP_START\s+10000\b',aids.read_text())
enum=re.search(r'enum UidOwnerMatchType : uint32_t \{.*?\n\};',header.read_text(),re.S).group()
r=reference.read_text()
for name in ['allowlist_xtbpf','denylist_xtbpf']:
 old='DEFINE_XTBPF_PROG(skfilter, '+name+')\n';assert r.count(old)==1;r=r.replace(old,'static int '+name)
oracles='\n'.join(m.extract(r,n) for n in ['allowlist_xtbpf','denylist_xtbpf'])
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
#include "Gta3xlwifiMeteredChainProgram.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <deque>
using namespace android::net::gta3xlwifi;
using C=CheckedUidChains;using V=C::Verdict;using F=C::Selector;using Image=UidChainProgram::Image;
namespace Oracle {
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
#define XTBPF_MATCH 1
#define XTBPF_NOMATCH 0
struct __sk_buff{uint32_t uid;};
static uint32_t bpf_get_socket_uid(const __sk_buff* skb){return skb->uid;}
struct UidOwnerValue{uint32_t iif,rule;};static UidOwnerValue entry;static uint32_t entryUid;static bool present;
static UidOwnerValue* bpf_uid_owner_map_lookup_elem(const uint32_t* uid){return present&&*uid==entryUid?&entry:nullptr;}
'''+enum+'\n'+m.extract(header.read_text(),'is_system_uid')+'\n'+oracles+r'''
}
unsigned cases=0,comparisons=0;
#define T(x) do{assert(x);++cases;}while(0)
bool rejects(const Image& image,size_t index,uint32_t raw){
 for(const auto& rule:image.at(index).rules){
  uint32_t uid=raw;
  if(rule.selector==F::RawAppId)uid=(raw==65534?0:raw)%100000;
  else assert(rule.selector==F::RawUid||!rule.uid);
  if(rule.uid&&(uid<rule.uid->first||uid>rule.uid->last))continue;
  switch(rule.verdict){case V::Return:return false;case V::Reject:return true;
   case V::DataSaverGoto:assert(index==1);return rejects(image,2,raw);default:assert(false);}
 }
 assert(false);return true;
}
struct Step{std::string command,output;int result=0;};
struct Kernel:IptablesRestoreInterface{
 std::deque<Step> steps;IptablesTarget family=V4;
 int execute(IptablesTarget f,const std::string& cmd,std::string* output)override{
  assert(f==family&&!steps.empty());Step s=steps.front();steps.pop_front();assert(cmd==s.command);
  if(output)*output=s.output;else assert(s.output.empty());return s.result;
 }
 void done(){assert(steps.empty());}
};
int main(){
 UidPolicy policy;Image image{{"sentinel",{}}};auto sentinel=image;
 T(MeteredChainProgram::compile(policy,nullptr)==-EINVAL);
 T(MeteredChainProgram::compile(policy,&image)==0&&image.size()==3);
 T(image[0].name=="g24_meter_deny"&&image[1].name=="g24_meter_allow"&&image[2].name=="g24_data_saver");
 T(image[0].rules.size()==1&&image[1].rules.size()==2&&image[2].rules.size()==1);
 auto base=image;for(int chain=1;chain<=9;chain++){assert(policy.setChainEnabled(chain,true)==0);assert(policy.replaceUidChain(chain,{10001})==0);}
 T(MeteredChainProgram::compile(policy,&image)==0&&image==base);
 T(policy.replaceUidChain(11,{10003,10001,10002,10002,INT_MAX})==0);
 T(policy.replaceUidChain(12,{10004,INT_MAX-1})==0);
 T(MeteredChainProgram::compile(policy,&image)==0&&image[0].rules.size()==3);
 T((image[0].rules[0].uid==C::UidRange{10001,10004}));T((image[0].rules[1].uid==C::UidRange{INT_MAX-1,INT_MAX}));
 UidPolicy huge;std::vector<int32_t> many;for(int i=0;i<30000;i++)many.push_back(10000+2*i);assert(huge.replaceUidChain(11,many)==0);image=sentinel;T(MeteredChainProgram::compile(huge,&image)==-E2BIG&&image==sentinel);
 // Deny has no core exemption; raw65534 is selectable. Happy/core wins only
 // over Data Saver, never over the preceding explicit user/admin deny chain.
 const uint32_t uids[]={0,1,9999,10000,10001,65534,65535,99999,100001,109999,110001,INT_MAX,UINT32_MAX};
 for(uint32_t raw:uids)for(unsigned alternate=0;alternate<2;alternate++)for(unsigned bits=0;bits<8;bits++)for(bool saver:{false,true}){
  UidPolicy p;p.setDataSaver(saver);Oracle::entryUid=alternate?20001:raw;Oracle::present=Oracle::entryUid<=INT_MAX;
  Oracle::entry.rule=(bits&1?static_cast<uint32_t>(Oracle::HAPPY_BOX_MATCH):0u)|(bits&2?static_cast<uint32_t>(Oracle::PENALTY_BOX_USER_MATCH):0u)|(bits&4?static_cast<uint32_t>(Oracle::PENALTY_BOX_ADMIN_MATCH):0u);
  if(Oracle::present)for(int chain:{10,11,12})if(bits&(1u<<(chain-10)))assert(p.replaceUidChain(chain,{static_cast<int32_t>(Oracle::entryUid)})==0);
  assert(MeteredChainProgram::compile(p,&image)==0);
  Oracle::__sk_buff skb{raw};bool deny=Oracle::denylist_xtbpf(&skb);bool allow=Oracle::allowlist_xtbpf(&skb);
  assert(rejects(image,0,raw)==deny);++comparisons;
  assert(rejects(image,1,raw)==(saver&&!allow));++comparisons;
  assert((rejects(image,0,raw)||rejects(image,1,raw))==(deny||(saver&&!allow)));++comparisons;
 }
 const std::string query="*filter\n-S g24_meter\nCOMMIT\n";
 const std::string empty="-N g24_meter\n",emptyWrite="*filter\n:g24_meter -\nCOMMIT\n";
 const std::string write="*filter\n:g24_meter -\n-A g24_meter -m gta3xlwifi_appid --appid 0:9999 -j RETURN\n-A g24_meter -m gta3xlwifi_raw_uid --raw_uid 4294967295:4294967295 -j REJECT\n-A g24_meter -m gta3xlwifi_raw_appid --raw_appid 0:9999 -j RETURN\n-A g24_meter -j REJECT\nCOMMIT\n";
 Image expected{{"g24_meter",{{C::UidRange{0,9999},V::Return,F::LookupAppId},{C::UidRange{UINT32_MAX,UINT32_MAX},V::Reject,F::RawUid},{C::UidRange{0,9999},V::Return,F::RawAppId},{std::nullopt,V::Reject}}}};
 for(auto family:{V4,V6}){
  Kernel k;k.family=family;C io(k);Image out=sentinel;
  const std::string rejection=family==V4?"icmp-port-unreachable":"icmp6-port-unreachable";
  const std::string list="-N g24_meter\n-A g24_meter -m gta3xlwifi_appid --appid 0:9999 -j RETURN\n-A g24_meter -m gta3xlwifi_raw_uid --raw_uid 4294967295:4294967295 -j REJECT --reject-with "+rejection+"\n-A g24_meter -m gta3xlwifi_raw_appid --raw_appid 0:9999 -j RETURN\n-A g24_meter -j REJECT --reject-with "+rejection+"\n";
  k.steps={{query,list}};T(io.read(family,{"g24_meter"},&out)==0&&out==expected);k.done();
  k.steps={{query,empty},{write,""},{query,list}};T(io.replace(family,expected)==0);k.done();
  k.steps={{query,empty},{write,"",-1},{emptyWrite,""},{query,empty}};T(io.replace(family,expected)==-EREMOTEIO);k.done();
  k.steps={{query,empty},{write,""},{query,empty},{emptyWrite,""},{query,empty}};T(io.replace(family,expected)==-EREMOTEIO);k.done();
  k.steps={{query,empty},{write,"",-1},{emptyWrite,"",-1}};T(io.replace(family,expected)==-EUCLEAN);k.done();
  for(const std::string& body:std::vector<std::string>{
   "-j REJECT", "-j REJECT --reject-with tcp-reset", "-j REJECT --reject-with "+std::string(family==V4?"icmp6-port-unreachable":"icmp-port-unreachable"),
   "-j DROP --reject-with "+rejection,"-j g24_reject","-j g24_data_saver","-g g24_data_saver",
   "-m gta3xlwifi_raw_uid --raw_uid 4294967296:4294967296 -j RETURN",
   "-m gta3xlwifi_raw_appid --raw_appid 100000:100000 -j RETURN",
   "-m gta3xlwifi_appid --appid 2:1 -j RETURN",
   "-m gta3xlwifi_raw_uid ! --raw_uid 1:2 -j RETURN"}){
   k.steps={{query,"-N g24_meter\n-A g24_meter "+body+"\n"}};out=sentinel;T(io.read(family,{"g24_meter"},&out)==-EPROTO&&out==sentinel);k.done();
  }
  const std::string q2="*filter\n-S g24_meter\n-S g24_data_saver\nCOMMIT\n";
  Image gotos{{"g24_meter",{{std::nullopt,V::DataSaverGoto}}},{"g24_data_saver",{{std::nullopt,V::Return}}}};
  k.steps={{q2,"-N g24_meter\n-A g24_meter -g g24_data_saver\n-N g24_data_saver\n-A g24_data_saver -j RETURN\n"}};
  T(io.read(family,{"g24_meter","g24_data_saver"},&out)==0&&out==gotos);k.done();
 }
 Image invalid{{"g24_meter",{{std::nullopt,V::DataSaverGoto}}}};T(C::validateImage(invalid)==-EINVAL);
 invalid.push_back({"g24_data_saver",{{std::nullopt,V::DataSaverGoto}}});T(C::validateImage(invalid)==-EINVAL);
 invalid[1].rules={{std::nullopt,V::Return}};T(C::validateImage(invalid)==0);
 invalid[1].rules={{C::UidRange{1,1},V::Return}};T(C::validateImage(invalid)==-EINVAL);
 invalid=expected;invalid[0].rules[0].selector=static_cast<F>(99);T(C::validateImage(invalid)==-EINVAL);
 invalid=expected;invalid[0].rules[0].uid.reset();T(C::validateImage(invalid)==-EINVAL);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.cpp').write_text(code);sources=[S/(n+'.cpp') for n in ['Gta3xlwifiUidPolicy','Gta3xlwifiCheckedUidChains','Gta3xlwifiUidChainProgram','Gta3xlwifiMeteredChainProgram']]
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=180);(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',r.stdout);assert match and int(match[1])>=50 and int(match[2])==1248
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,reference,header,aids,O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[x.with_suffix('.h') for x in sources]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_android17_metered_predicate_comparisons':int(match[2]),'stderr':r.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; actual typed metered programs vs A17 xtbpf, fatal UBSan')
