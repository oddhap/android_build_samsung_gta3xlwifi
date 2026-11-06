
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
}
static inline bool is_system_uid(uint32_t uid) {
    // MIN_SYSTEM_UID is AID_ROOT == 0, so uint32_t is *always* >= 0
    // MAX_SYSTEM_UID is AID_NOBODY == 9999, while AID_APP_START == 10000
    return ((uid % AID_USER_OFFSET) < AID_APP_START);
}
function bool skip_owner_match(const SkbIpPacketData* const packet,
                               const struct egress_bool egress) {
    if (packet->ip_version == 0) return false;

    if (packet->ip_proto == IPPROTO_ESP) return true;

    if (packet->ip_proto != IPPROTO_TCP) return false;

    // Always allow RST's, and additionally allow ingress FINs
    return packet->tcp_flags & (TCP_FLAG8_RST | (egress.egress ? 0 : TCP_FLAG8_FIN));
}
function int bpf_owner_match(const SkbIpPacketData* const packet,
                             struct __sk_buff* skb,
                             uint32_t uid,
                             const struct egress_bool egress,
                             const struct kver_uint kver,
                             const struct sdk_level_uint lvl) {
    if (is_system_uid(uid)) return PASS;

    if (skip_owner_match(packet, egress)) return PASS;

    BpfConfig enabledRules = getConfig(UID_RULES_CONFIGURATION_KEY);

    // BACKGROUND match does not apply to loopback traffic
    if (skb->ifindex == 1) enabledRules &= ~BACKGROUND_MATCH;

    UidOwnerValue* uidEntry = bpf_uid_owner_map_lookup_elem(&uid);
    uint32_t uidRules = uidEntry ? uidEntry->rule : 0;
    uint32_t allowed_iif = uidEntry ? uidEntry->iif : 0;

    if (isBlockedByUidRules(enabledRules, uidRules)) return DROP;

    if (!egress.egress && skb->ifindex != 1) {
        if (ingress_should_discard(packet, skb, kver)) return DROP;
        if (uidRules & IIF_MATCH) {
            if (allowed_iif && skb->ifindex != allowed_iif) {
                // Drops packets not coming from lo nor the allowed interface
                // allowed interface=0 is a wildcard and does not drop packets
                return DROP_UNLESS_DNS;
            }
        } else if (uidRules & LOCKDOWN_VPN_MATCH) {
            // Drops packets not coming from lo and rule does not have IIF_MATCH but has
            // LOCKDOWN_VPN_MATCH
            return DROP_UNLESS_DNS;
        }
    }

    if (API_IS_AT_LEAST(lvl, 25Q2) && skb->ifindex == 1) {
        // TODO: sdksandbox localhost restrictions
    }

    return PASS;
}
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
