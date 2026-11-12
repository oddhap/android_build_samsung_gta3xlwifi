
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
int main(){unsigned cases=0;auto check=[&](bool b){assert(b);++cases;};
 for(auto family:{V4,V6}){
  Kernel k;k.family=family;C writer(k);std::vector<C::Chain> out;
  k.steps={{query,oldList}};check(writer.read(family,{"g24_uid"},&out)==0&&out==image(10001));k.done();
  k.steps={{query,oldList}};check(writer.replace(family,image(10001))==0);k.done();
  k.steps={{query,oldList},{newWrite,""},{query,newList}};check(writer.replace(family,image(110001))==0);k.done();
  // Even a failed command may have committed before its acknowledgement failed.
  k.steps={{query,oldList},{newWrite,"",-1},{oldWrite,""},{query,oldList}};check(writer.replace(family,image(110001))==-EREMOTEIO);k.done();
  for(auto bad:std::vector<std::string>{"bad",oldList}){
   k.steps={{query,oldList},{newWrite,""},{query,bad},{oldWrite,""},{query,oldList}};check(writer.replace(family,image(110001))==-EREMOTEIO);k.done();
  }
  k.steps={{query,oldList},{newWrite,"",-1},{oldWrite,"",-1}};check(writer.replace(family,image(110001))==-EUCLEAN);k.done();
  k.steps={{query,oldList},{newWrite,"",-1},{oldWrite,""},{query,"",-1}};check(writer.replace(family,image(110001))==-EUCLEAN);k.done();
  k.steps={{query,oldList},{newWrite,"",-1},{oldWrite,""},{query,newList}};check(writer.replace(family,image(110001))==-EUCLEAN);k.done();
  k.steps={{query,"",5}};out=image(777);check(writer.read(family,{"g24_uid"},&out)==-EREMOTEIO&&out==image(777));k.done();
  for(auto bad:std::vector<std::string>{"","-N foreign\n",oldList+"-N g24_uid\n","-P g24_uid ACCEPT\n","-N g24_uid\n-A g24_uid -j ACCEPT\n","-N g24_uid\n-A g24_uid -m owner --uid-owner -1 -j DROP\n","-N g24_uid\n-A g24_uid -m owner --uid-owner 2147483648 -j DROP\n","-N g24_uid\n-A g24_uid -m owner --uid-owner 20-10 -j DROP\n","-N g24_uid\n-A g24_uid -m owner --uid-owner 1-2-3 -j DROP\n","-N g24_uid\n-A g24_other -j DROP\n","-N g24_uid\n-A g24_uid -p tcp -j DROP\n","-N g24_uid\n-A g24_uid -j DROP extra\n",std::string("-N g24_uid\0bad",14),"-N g24_uid\r\n","-N g24_uid\v\n",std::string(1024*1024+1,'x')}){
   k.steps={{query,bad}};out=image(777);check(writer.read(family,{"g24_uid"},&out)==-EPROTO&&out==image(777));k.done();
  }
  k.steps={{query,"bad"}};check(writer.replace(family,image(110001))==-EPROTO);k.done();
  k.steps={{query,"-N g24_uid\n-A g24_uid -m owner --uid-owner 0-2147483647 -j DROP\n"}};check(writer.read(family,{"g24_uid"},&out)==0&&out[0].rules[0].uid==C::UidRange{0,INT_MAX});k.done();
  for(const auto& names:std::vector<std::vector<std::string>>{{},{"g24_uid","g24_uid"},{"foreign"},{"g24_"},{"g24_bad\nCOMMIT"},{std::string(29,'a')}}){check(writer.read(family,names,&out)==-EINVAL);k.done();}
  auto bad=image(10001);bad[0].rules[0].uid=C::UidRange{20,10};check(writer.replace(family,bad)==-EINVAL);k.done();
  bad=image(10001);bad[0].rules[0].verdict=static_cast<V>(77);check(writer.replace(family,bad)==-EINVAL);k.done();
  check(writer.read(family,{"g24_uid"},nullptr)==-EINVAL);k.done();
  auto huge=image(10001);huge[0].rules.assign(65536,{C::UidRange{10001,10001},V::Return});check(writer.replace(family,huge)==-E2BIG);k.done();
  const std::string q2="*filter\n-S g24_uid\n-S g24_meter\nCOMMIT\n";
  const std::string tailOld="-N g24_meter\n-A g24_meter -m owner --uid-owner 100000-109999 -j RETURN\n-A g24_meter -j DROP\n";
  const std::string tailNew="-N g24_meter\n-A g24_meter -m owner --uid-owner 200000-209999 -j RETURN\n-A g24_meter -j DROP\n";
  const std::string w2old="*filter\n:g24_uid -\n-A g24_uid -m owner --uid-owner 10001 -j RETURN\n-A g24_uid -j DROP\n:g24_meter -\n-A g24_meter -m owner --uid-owner 100000-109999 -j RETURN\n-A g24_meter -j DROP\nCOMMIT\n";
  const std::string w2new="*filter\n:g24_uid -\n-A g24_uid -m owner --uid-owner 110001 -j RETURN\n-A g24_uid -j DROP\n:g24_meter -\n-A g24_meter -m owner --uid-owner 200000-209999 -j RETURN\n-A g24_meter -j DROP\nCOMMIT\n";
  auto two=image(110001);two.push_back({"g24_meter",{{C::UidRange{200000,209999},V::Return},{std::nullopt,V::Drop}}});
  k.steps={{q2,oldList+tailOld},{w2new,""},{q2,newList+tailNew}};check(writer.replace(family,two)==0);k.done();
  k.steps={{q2,oldList+tailOld},{w2new,""},{q2,newList+tailOld},{w2old,""},{q2,oldList+tailOld}};check(writer.replace(family,two)==-EREMOTEIO);k.done();
  k.steps={{q2,oldList}};out=image(777);check(writer.read(family,{"g24_uid","g24_meter"},&out)==-EPROTO&&out==image(777));k.done();

 }
 Kernel k;C writer(k);std::vector<C::Chain> out;check(writer.read(V4V6,{"g24_uid"},&out)==-EINVAL);check(writer.replace(V4V6,image(10001))==-EINVAL);k.done();
 std::cout<<"passed_cases="<<cases<<"\n";
}
