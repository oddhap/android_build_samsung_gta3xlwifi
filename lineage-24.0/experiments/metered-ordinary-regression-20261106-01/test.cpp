
#include "Gta3xlwifiUidChainProgram.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
using android::net::gta3xlwifi::UidPolicy;
using android::net::gta3xlwifi::UidChainProgram;
using C=android::net::gta3xlwifi::CheckedUidChains;
namespace Oracle{using BpfConfig=uint32_t;
enum UidOwnerMatchType : uint32_t {
    NO_MATCH = 0,
    HAPPY_BOX_MATCH = (1 << 0),
    PENALTY_BOX_USER_MATCH = (1 << 1),
    DOZABLE_MATCH = (1 << 2),
    STANDBY_MATCH = (1 << 3),
    POWERSAVE_MATCH = (1 << 4),
    RESTRICTED_MATCH = (1 << 5),
    LOW_POWER_STANDBY_MATCH = (1 << 6),
    IIF_MATCH = (1 << 7),
    LOCKDOWN_VPN_MATCH = (1 << 8),
    OEM_DENY_1_MATCH = (1 << 9),
    OEM_DENY_2_MATCH = (1 << 10),
    OEM_DENY_3_MATCH = (1 << 11),
    BACKGROUND_MATCH = (1 << 12),
    PENALTY_BOX_ADMIN_MATCH = (1 << 13),
};
#define DROP_IF_SET (STANDBY_MATCH | OEM_DENY_1_MATCH | OEM_DENY_2_MATCH | OEM_DENY_3_MATCH)
// DROP_IF_UNSET is set of rules that should DROP if globally enabled, and per-uid bit is NOT set
#define DROP_IF_UNSET (DOZABLE_MATCH | POWERSAVE_MATCH | RESTRICTED_MATCH \
                        | LOW_POWER_STANDBY_MATCH | BACKGROUND_MATCH)


static inline bool isBlockedByUidRules(BpfConfig enabledRules, uint32_t uidRules) {
    return enabledRules & (DROP_IF_SET | DROP_IF_UNSET) & (uidRules ^ DROP_IF_UNSET);
}}

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
