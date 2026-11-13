
#include "Gta3xlwifiCheckedUidChains.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <deque>
#include <iostream>
using C=android::net::gta3xlwifi::CheckedUidChains;
using V=C::Verdict;
struct Step{std::string command,output;int result=0;};
struct Kernel:IptablesRestoreInterface{
 std::deque<Step> steps;IptablesTarget family=V4;unsigned calls=0;
 int execute(IptablesTarget f,const std::string& command,std::string* output)override{
  assert(f==family&&!steps.empty());auto step=steps.front();steps.pop_front();++calls;
  assert(command==step.command);if(output)*output=step.output;else assert(step.output.empty());return step.result;
 }
 void done(){assert(steps.empty());}
};
const std::string query="*filter\n-S g24_uid\nCOMMIT\n";
const std::string oldList="-N g24_uid\n-A g24_uid -m owner --uid-owner 10001 -j RETURN\n-A g24_uid -j DROP\n";
const std::string newList="-N g24_uid\n-A g24_uid -m owner --uid-owner 110001 -j RETURN\n-A g24_uid -j DROP\n";
const std::string oldWrite="*filter\n:g24_uid -\n-A g24_uid -m owner --uid-owner 10001 -j RETURN\n-A g24_uid -j DROP\nCOMMIT\n";
const std::string newWrite="*filter\n:g24_uid -\n-A g24_uid -m owner --uid-owner 110001 -j RETURN\n-A g24_uid -j DROP\nCOMMIT\n";
std::vector<C::Chain> image(unsigned uid){return {{"g24_uid",{{C::UidRange{uid,uid},V::Return},{std::nullopt,V::Drop}}}};}

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
