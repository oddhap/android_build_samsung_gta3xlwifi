
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <linux/netfilter/gta3xlwifi_ingress.h>
#include <linux/netfilter/gta3xlwifi_socket_tables.h>
typedef uint32_t u32;typedef uint8_t u8;
#include <net/gta3xlwifi_packet.h>
#define GTA3XLWIFI_SOCKET_TABLE "g24sock"
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NFPROTO_UNSPEC 0
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define EXPORT_SYMBOL_GPL(x)
#define __read_mostly
#define __init
#define module_init(x)
#define THIS_MODULE NULL
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
struct net_device{u32 ifindex;};struct sk_buff{unsigned identity;};
struct xt_action_param{unsigned hooknum;const struct net_device*in;const void*matchinfo;};
struct xt_mtchk_param{const char*table;unsigned family;const void*matchinfo;};
struct xt_match{const char*name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void*me;};
struct xt_entry_match{union{struct{const struct xt_match*match;}kernel;}u;};
static unsigned init_user_ns,other_ns;static void*user_ns=&init_user_ns;
static void*current_user_ns(void){return user_ns;}
static bool have_context=true,dns,output,parse_result;
static struct gta3xlwifi_packet packet;
static struct sk_buff frame={1},clone={2};
static bool gta3xlwifi_socket_context_packet(const struct sk_buff*s,bool*d,bool*o){if(!have_context||s!=&frame)return false;*d=dns;*o=output;return true;}
bool gta3xlwifi_parse_packet(const struct sk_buff*s,struct gta3xlwifi_packet*p){assert(s==&frame);*p=packet;return parse_result;}
static int register_error;static unsigned registrations;
static int xt_register_matches(struct xt_match*,unsigned);
static bool ingress_registered;
u32 gta3xlwifi_ingress_features(void)
{
    return READ_ONCE(ingress_registered) ? GTA3XLWIFI_UID_CAP_INGRESS_MATCHES : 0;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_ingress_features);
static bool ingress_context(const struct sk_buff *skb, const struct xt_action_param *par,
                            bool dns_exempt, u32 *ifindex)
{
    bool dns, output;
    if (!skb || !par || par->hooknum != NF_INET_LOCAL_IN ||
        !gta3xlwifi_socket_context_packet(skb, &dns, &output) || output ||
        (dns_exempt && dns))
        return false;
    *ifindex = par->in ? par->in->ifindex : 0;
    return *ifindex != 1;
}
static bool bad_iif_match(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct gta3xlwifi_bad_iif_match *info = par->matchinfo;
    u32 ifindex;
    return ingress_context(skb, par, true, &ifindex) &&
           (!info->allowed_ifindex || ifindex != info->allowed_ifindex);
}
static bool ingress_discard_match(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct gta3xlwifi_ingress_discard_match *info = par->matchinfo;
    struct gta3xlwifi_packet packet;
    u32 ifindex;
    if (!ingress_context(skb, par, false, &ifindex) ||
        ifindex == info->allowed_ifindex[0] || ifindex == info->allowed_ifindex[1])
        return false;
    /* L3 destination may be valid even when parsing L4 failed. Exact A17 parser
     * initializes every byte. Its relative-header backport already exists here;
     * do not fake the kernel version to disable this protection. */
    gta3xlwifi_parse_packet(skb, &packet);
    return packet.ip_version && !memcmp(&packet.daddr, info->daddr, 16);
}
static int ingress_check(const struct xt_mtchk_param *par)
{
    if (current_user_ns() != &init_user_ns ||
        strcmp(par->table, GTA3XLWIFI_SOCKET_TABLE) ||
        (par->family != NFPROTO_IPV4 && par->family != NFPROTO_IPV6))
        return -EINVAL;
    return 0;
}
static int bad_iif_check(const struct xt_mtchk_param *par)
{
    const struct gta3xlwifi_bad_iif_match *info = par->matchinfo;
    int result = ingress_check(par);
    return result ? result : info->reserved || info->allowed_ifindex > INT_MAX ? -EINVAL : 0;
}
static int ingress_discard_check(const struct xt_mtchk_param *par)
{
    const struct gta3xlwifi_ingress_discard_match *info = par->matchinfo;
    static const u8 zero[16];
    static const u8 mapped_zero[16] = {0,0,0,0,0,0,0,0,0,0,255,255,0,0,0,0};
    int result = ingress_check(par);
    if (result)
        return result;
    /* A17 relies on these unassigned addresses never being in its map. */
    return info->reserved || info->allowed_ifindex[0] > INT_MAX ||
           info->allowed_ifindex[1] > INT_MAX || !memcmp(info->daddr, zero, 16) ||
           !memcmp(info->daddr, mapped_zero, 16) ? -EINVAL : 0;
}
static struct xt_match ingress_matches[] __read_mostly = {
    {
        .name = GTA3XLWIFI_BAD_IIF_MATCH, .revision = 0, .family = NFPROTO_UNSPEC,
        .hooks = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_LOCAL_OUT),
        .match = bad_iif_match, .checkentry = bad_iif_check,
        .matchsize = sizeof(struct gta3xlwifi_bad_iif_match), .me = THIS_MODULE,
    }, {
        .name = GTA3XLWIFI_INGRESS_DISCARD_MATCH, .revision = 0, .family = NFPROTO_UNSPEC,
        .hooks = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_LOCAL_OUT),
        .match = ingress_discard_match, .checkentry = ingress_discard_check,
        .matchsize = sizeof(struct gta3xlwifi_ingress_discard_match), .me = THIS_MODULE,
    },
};
static int __init ingress_init(void)
{
    int result = xt_register_matches(ingress_matches, ARRAY_SIZE(ingress_matches));
    if (!result)
        WRITE_ONCE(ingress_registered, true);
    return result;
}
module_init(ingress_init);

static bool socket_match_safe(const struct xt_entry_match *match)
{
    const char *name = match->u.kernel.match->name;
    return !strcmp(name, "gta3xlwifi_raw_uid") ||
           !strcmp(name, "gta3xlwifi_raw_appid") ||
           !strcmp(name, "gta3xlwifi_owner_skip") ||
           !strcmp(name, "gta3xlwifi_non_loopback") ||
           !strcmp(name, "gta3xlwifi_bad_iif") ||
           !strcmp(name, "gta3xlwifi_ingress_discard");
}
static int xt_register_matches(struct xt_match*m,unsigned n){assert(m==ingress_matches&&n==2);++registrations;return register_error;}
#define function
#define PASS 1
#define DROP 0
#define DROP_UNLESS_DNS 2
#define UID_RULES_CONFIGURATION_KEY 0
#define API_IS_AT_LEAST(level,version) 0
#define KVER_IS_AT_LEAST(k,a,b) ((k).version >= (((a)<<16)|((b)<<8)))
struct kver_uint{unsigned version;};struct sdk_level_uint{unsigned version;};struct egress_bool{bool egress;};
struct __sk_buff{u32 ifindex;};
typedef struct gta3xlwifi_packet SkbIpPacketData;
typedef struct{struct in6_addr daddr;}IngressDiscardKey;
typedef struct{u32 iif[2];}IngressDiscardValue;
typedef struct{u32 rule,iif;}UidOwnerValue;typedef u32 BpfConfig;
static bool protect;static struct in6_addr protected_addr;static IngressDiscardValue protected_iif;
static UidOwnerValue uid_entry;
static IngressDiscardValue*bpf_ingress_discard_map_lookup_elem(const IngressDiscardKey*k){return protect&&!memcmp(&k->daddr,&protected_addr,16)?&protected_iif:NULL;}
static bool is_system_uid(u32 uid){assert(uid==10001);return false;}
static bool skip_owner_match(const SkbIpPacketData*p,struct egress_bool e){(void)p;(void)e;return false;}
static BpfConfig getConfig(unsigned key){assert(key==0);return 0;}
static UidOwnerValue*bpf_uid_owner_map_lookup_elem(const u32*uid){assert(*uid==10001);return &uid_entry;}
static bool isBlockedByUidRules(u32 enabled,u32 rules){assert(!enabled);(void)rules;return false;}
enum {IIF_MATCH = (1 << 7)};
enum {LOCKDOWN_VPN_MATCH = (1 << 8)};
enum {BACKGROUND_MATCH = (1 << 12)};

function bool ingress_should_discard(const SkbIpPacketData* const packet,
                                     struct __sk_buff* skb,
                                     const struct kver_uint kver) {
    // Require 4.19, since earlier kernels don't have bpf_skb_load_bytes_relative() which
    // provides relative to L3 header reads.  Without that we could fetch the wrong bytes.
    // Additionally earlier bpf verifiers are much harder to please.
    if (!KVER_IS_AT_LEAST(kver, 4, 19)) return false;

    if (packet->ip_version == 0) return false;

    IngressDiscardKey k = { .daddr = packet->daddr };

    // we didn't check for load success, because destination bytes will be zeroed if
    // bpf_skb_load_bytes_net() fails, instead we rely on daddr of '::' and '::ffff:0.0.0.0'
    // never being present in the map itself

    IngressDiscardValue* v = bpf_ingress_discard_map_lookup_elem(&k);
    if (!v) return false;  // lookup failure -> no protection in place -> allow
    // if (skb->ifindex == 1) return false;  // allow 'lo', but can't happen - see callsite
    if (skb->ifindex == v->iif[0]) return false;  // allowed interface
    if (skb->ifindex == v->iif[1]) return false;  // allowed interface
    return true;  // disallowed interface
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
static unsigned cases,owner_comparisons,discard_comparisons;
#define T(x) do{assert(x);++cases;}while(0)
static int oracle_regression_main(void){
 T(sizeof(struct gta3xlwifi_bad_iif_match)==8&&sizeof(struct gta3xlwifi_ingress_discard_match)==28&&offsetof(struct gta3xlwifi_ingress_discard_match,allowed_ifindex)==16);
 T(gta3xlwifi_ingress_features()==0);register_error=-EINVAL;T(ingress_init()==-EINVAL&&gta3xlwifi_ingress_features()==0&&registrations==1);register_error=0;T(ingress_init()==0&&gta3xlwifi_ingress_features()==512&&registrations==2);
 T(ingress_matches[0].matchsize==8&&ingress_matches[1].matchsize==28&&ingress_matches[0].hooks==10&&ingress_matches[1].hooks==10);
 for(unsigned i=0;i<2;i++){struct xt_entry_match em={.u.kernel.match=&ingress_matches[i]};T(socket_match_safe(&em));}struct xt_match foreign={.name="owner"};struct xt_entry_match em={.u.kernel.match=&foreign};T(!socket_match_safe(&em));
 struct gta3xlwifi_bad_iif_match bad={17,0};struct gta3xlwifi_ingress_discard_match discard={{0}, {2,17},0};discard.daddr[15]=1;
 struct xt_mtchk_param check={"g24sock",NFPROTO_IPV4,&bad};T(bad_iif_check(&check)==0);bad.reserved=1;T(bad_iif_check(&check)==-EINVAL);bad.reserved=0;bad.allowed_ifindex=UINT32_MAX;T(bad_iif_check(&check)==-EINVAL);bad.allowed_ifindex=0;T(bad_iif_check(&check)==0);
 check.matchinfo=&discard;T(ingress_discard_check(&check)==0);discard.reserved=1;T(ingress_discard_check(&check)==-EINVAL);discard.reserved=0;discard.allowed_ifindex[0]=UINT32_MAX;T(ingress_discard_check(&check)==-EINVAL);discard.allowed_ifindex[0]=2;
 memset(discard.daddr,0,16);T(ingress_discard_check(&check)==-EINVAL);discard.daddr[10]=discard.daddr[11]=255;T(ingress_discard_check(&check)==-EINVAL);discard.daddr[15]=1;T(ingress_discard_check(&check)==0);
 for(unsigned family=0;family<4;family++){check.family=family;T(ingress_discard_check(&check)==(family==2?0:-EINVAL));}check.family=NFPROTO_IPV6;T(ingress_discard_check(&check)==0);check.table="filter";T(ingress_discard_check(&check)==-EINVAL);check.table="g24sock";user_ns=&other_ns;T(ingress_discard_check(&check)==-EINVAL);user_ns=&init_user_ns;
 const u32 indices[]={0,1,2,17,INT_MAX};const u32 allowed[]={0,2,17};struct net_device dev={17};struct xt_action_param action={NF_INET_LOCAL_IN,&dev,&bad};struct __sk_buff oracle={17};packet.ip_version=4;
 // IIF-present wildcard0 suppresses lockdown. The native compiler must emit no
 // drop entry for that UID; absent-IIF lockdown uses bad_iif allowed0 instead.
 for(unsigned present=0;present<2;present++)for(unsigned lockdown=0;lockdown<2;lockdown++)for(unsigned a=0;a<3;a++)for(unsigned i=0;i<5;i++)for(unsigned d=0;d<2;d++)for(unsigned o=0;o<2;o++){
  dns=d;output=o;dev.ifindex=oracle.ifindex=indices[i];action.hooknum=output?NF_INET_LOCAL_OUT:NF_INET_LOCAL_IN;uid_entry=(UidOwnerValue){(present?IIF_MATCH:0)|(lockdown?LOCKDOWN_VPN_MATCH:0),allowed[a]};
  int match=bpf_owner_match(&packet,&oracle,10001,(struct egress_bool){output},(struct kver_uint){(4<<16)|(19<<8)},(struct sdk_level_uint){0});bool expected=match==DROP||(match==DROP_UNLESS_DNS&&!dns);
  bool have_rule=present?allowed[a]!=0:lockdown;bad.allowed_ifindex=present?allowed[a]:0;bool actual=have_rule&&bad_iif_match(&frame,&action);assert(actual==expected);++owner_comparisons;
 }
 // Exact A17 discard expression, including partial L4 parse, two allowed
 // interfaces, loopback/output and DNS having NO discard exemption.
 protect=true;protected_addr=(struct in6_addr){{{0}}};protected_addr.s6_addr[15]=1;memcpy(discard.daddr,&protected_addr,16);action.matchinfo=&discard;
 for(unsigned version=0;version<3;version++)for(unsigned a=0;a<3;a++)for(unsigned b=0;b<3;b++)for(unsigned i=0;i<5;i++)for(unsigned d=0;d<2;d++)for(unsigned o=0;o<2;o++)for(unsigned same=0;same<2;same++)for(unsigned parsed=0;parsed<2;parsed++){
  dns=d;output=o;parse_result=parsed;dev.ifindex=oracle.ifindex=indices[i];action.hooknum=output?NF_INET_LOCAL_OUT:NF_INET_LOCAL_IN;discard.allowed_ifindex[0]=protected_iif.iif[0]=allowed[a];discard.allowed_ifindex[1]=protected_iif.iif[1]=allowed[b];packet.ip_version=version?version==1?4:6:0;packet.daddr=protected_addr;if(!same)packet.daddr.s6_addr[15]=2;
  bool expected=!output&&oracle.ifindex!=1&&ingress_should_discard(&packet,&oracle,(struct kver_uint){(4<<16)|(19<<8)});assert(ingress_discard_match(&frame,&action)==expected);++discard_comparisons;
 }
 output=false;dns=false;dev.ifindex=17;action.hooknum=NF_INET_LOCAL_IN;action.matchinfo=&bad;bad.allowed_ifindex=0;T(bad_iif_match(&frame,&action));T(!bad_iif_match(&clone,&action));have_context=false;T(!bad_iif_match(&frame,&action));have_context=true;u32 sentinel=777;T(!ingress_context(NULL,&action,false,&sentinel)&&sentinel==777);T(!ingress_context(&frame,NULL,false,&sentinel)&&sentinel==777);action.hooknum=2;T(!bad_iif_match(&frame,&action));action.hooknum=NF_INET_LOCAL_IN;action.in=NULL;T(bad_iif_match(&frame,&action));
 printf("passed_cases=%u owner_comparisons=%u discard_comparisons=%u\n",cases,owner_comparisons,discard_comparisons);
return 0;}

int g24OracleChecks(void){return oracle_regression_main();}
int g24OracleIif(uint32_t flags,uint32_t allowed,uint32_t index,int is_dns,int is_output){
 protect=false;uid_entry=(UidOwnerValue){flags,allowed};struct __sk_buff s={index};struct gta3xlwifi_packet p={0};
 int verdict=bpf_owner_match(&p,&s,10001,(struct egress_bool){is_output},(struct kver_uint){(4<<16)|(19<<8)},(struct sdk_level_uint){0});
 return verdict==DROP||(verdict==DROP_UNLESS_DNS&&!is_dns);
}
int g24OracleDiscard(const uint8_t*configured,const uint8_t*actual,uint32_t first,uint32_t second,uint32_t index,int is_output,unsigned version){
 protect=true;memcpy(&protected_addr,configured,16);protected_iif=(IngressDiscardValue){{first,second}};struct __sk_buff s={index};struct gta3xlwifi_packet p={0};p.ip_version=version;memcpy(&p.daddr,actual,16);
 return !is_output&&index!=1&&ingress_should_discard(&p,&s,(struct kver_uint){(4<<16)|(19<<8)});
}
