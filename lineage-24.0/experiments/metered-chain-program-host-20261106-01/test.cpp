
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
static inline bool is_system_uid(uint32_t uid) {
    // MIN_SYSTEM_UID is AID_ROOT == 0, so uint32_t is *always* >= 0
    // MAX_SYSTEM_UID is AID_NOBODY == 9999, while AID_APP_START == 10000
    return ((uid % AID_USER_OFFSET) < AID_APP_START);
}
static int allowlist_xtbpf(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    if (is_system_uid(sock_uid)) return XTBPF_MATCH;

    // kernel's DEFAULT_OVERFLOWUID is 65534, this is the overflow 'nobody' uid,
    // usually this being returned means that skb->sk is NULL during RX
    // (early decap socket lookup failure), which commonly happens for incoming
    // packets to an unconnected udp socket.
    // But it can also happen for egress from a timewait socket.
    // Let's treat such cases as 'root' which is_system_uid()
    if (sock_uid == 65534) return XTBPF_MATCH;

    UidOwnerValue* allowlistMatch = bpf_uid_owner_map_lookup_elem(&sock_uid);
    if (allowlistMatch) return allowlistMatch->rule & HAPPY_BOX_MATCH ? XTBPF_MATCH : XTBPF_NOMATCH;
    return XTBPF_NOMATCH;
}
static int denylist_xtbpf(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    UidOwnerValue* denylistMatch = bpf_uid_owner_map_lookup_elem(&sock_uid);
    uint32_t penalty_box = PENALTY_BOX_USER_MATCH | PENALTY_BOX_ADMIN_MATCH;
    if (denylistMatch) return denylistMatch->rule & penalty_box ? XTBPF_MATCH : XTBPF_NOMATCH;
    return XTBPF_NOMATCH;
}
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
  Oracle::entry.rule=(bits&1?Oracle::HAPPY_BOX_MATCH:0)|(bits&2?Oracle::PENALTY_BOX_USER_MATCH:0)|(bits&4?Oracle::PENALTY_BOX_ADMIN_MATCH:0);
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
