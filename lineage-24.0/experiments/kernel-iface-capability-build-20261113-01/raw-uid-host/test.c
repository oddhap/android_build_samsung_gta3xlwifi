
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/netfilter/gta3xlwifi_socket_uid.h>
#include <linux/netfilter/gta3xlwifi_appid.h>
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define NFPROTO_UNSPEC 0
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NF_INET_LOCAL_IN 1
#define NF_INET_FORWARD 2
#define NF_INET_LOCAL_OUT 3
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
#define XTBPF_MATCH 1
#define XTBPF_NOMATCH 0
typedef uint32_t uid_t;
struct user_namespace{uint32_t offset;};static struct user_namespace init_user_ns={0},other_ns={100000};static struct user_namespace* current_ns=&init_user_ns;
static struct user_namespace* current_user_ns(void){return current_ns;}
static int overflowuid=65534;
struct net{struct user_namespace* user_ns;};static struct net initial_net={&init_user_ns},other_net={&other_ns};
struct sock{bool full;uid_t sk_uid;struct net* net;};
struct sk_buff{struct sock* sk;};struct xt_action_param{const void* matchinfo;};struct xt_mtchk_param{const void* matchinfo;unsigned family;};
static struct sock* skb_to_full_sk(const struct sk_buff* skb){return skb->sk;}
static bool sk_fullsock(const struct sock* sk){return sk->full;}
static struct net* sock_net(const struct sock* sk){return sk->net;}
static uid_t sock_net_uid(const struct net* n,const struct sock* sk){assert(n==sk->net);return sk->sk_uid;}
static uid_t from_kuid_munged(const struct user_namespace* n,uid_t uid){if(uid==UINT32_MAX||uid<n->offset)return overflowuid;return uid-n->offset;}
struct xt_match{const char* name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void* me;};
static int register_result;static unsigned registers;
static int xt_register_matches(struct xt_match* matches,unsigned count){assert(count==2&&matches[0].matchsize==8&&matches[1].matchsize==8);++registers;return register_result;}
struct __sk_buff{uint32_t reference_uid;};
static uint32_t bpf_get_socket_uid(const struct __sk_buff* skb){return skb->reference_uid;}
typedef struct{uint32_t iif,rule;}UidOwnerValue;static UidOwnerValue entry;static uint32_t entry_uid;static bool present;
static UidOwnerValue* bpf_uid_owner_map_lookup_elem(const uint32_t* uid){return present&&*uid==entry_uid?&entry:NULL;}

typedef uint32_t u32;
static bool gta3xlwifi_socket_context_uid(const struct sk_buff*s,u32*u){(void)s;(void)u;return false;} /* outside private evaluator regression */
enum UidOwnerMatchType {
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
static uid_t gta3xlwifi_raw_socket_uid(const struct sk_buff *skb)
{
	struct sock *sk;
	struct net *net;
	u32 snapshot;

	if (gta3xlwifi_socket_context_uid(skb, &snapshot))
		return snapshot;
	sk = skb_to_full_sk(skb);
	if (!sk || !sk_fullsock(sk))
		return overflowuid;
	net = sock_net(sk);
	return from_kuid_munged(net->user_ns, sock_net_uid(net, sk));
}
static bool gta3xlwifi_raw_uid_mt(const struct sk_buff *skb,
                                struct xt_action_param *par)
{
	const struct gta3xlwifi_socket_uid_match *info = par->matchinfo;
	uid_t uid;

	if (!skb)
		return false;
	uid = gta3xlwifi_raw_socket_uid(skb);
	return uid >= info->minimum && uid <= info->maximum;
}
static bool gta3xlwifi_raw_appid_mt(const struct sk_buff *skb,
                                  struct xt_action_param *par)
{
	const struct gta3xlwifi_socket_uid_match *info = par->matchinfo;
	uid_t uid;

	if (!skb)
		return false;
	uid = gta3xlwifi_raw_socket_uid(skb);
	if (uid == 65534)
		uid = 0;
	uid %= GTA3XLWIFI_APPID_USER_OFFSET;
	return uid >= info->minimum && uid <= info->maximum;
}
static int gta3xlwifi_raw_uid_check(const struct xt_mtchk_param *par)
{
	const struct gta3xlwifi_socket_uid_match *info = par->matchinfo;

	if (current_user_ns() != &init_user_ns ||
	    (par->family != NFPROTO_IPV4 && par->family != NFPROTO_IPV6) ||
	    info->minimum > info->maximum)
		return -EINVAL;
	return 0;
}
static int gta3xlwifi_raw_appid_check(const struct xt_mtchk_param *par)
{
	const struct gta3xlwifi_socket_uid_match *info = par->matchinfo;
	int result = gta3xlwifi_raw_uid_check(par);

	if (result)
		return result;
	return info->maximum < GTA3XLWIFI_APPID_USER_OFFSET ? 0 : -EINVAL;
}
static struct xt_match gta3xlwifi_raw_uid_reg[] __read_mostly = {
	{
		.name = GTA3XLWIFI_RAW_UID_MATCH,
		.revision = 0,
		.family = NFPROTO_UNSPEC,
		.hooks = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
		         (1 << NF_INET_LOCAL_OUT),
		.match = gta3xlwifi_raw_uid_mt,
		.checkentry = gta3xlwifi_raw_uid_check,
		.matchsize = sizeof(struct gta3xlwifi_socket_uid_match),
		.me = THIS_MODULE,
	}, {
		.name = GTA3XLWIFI_RAW_APPID_MATCH,
		.revision = 0,
		.family = NFPROTO_UNSPEC,
		.hooks = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
		         (1 << NF_INET_LOCAL_OUT),
		.match = gta3xlwifi_raw_appid_mt,
		.checkentry = gta3xlwifi_raw_appid_check,
		.matchsize = sizeof(struct gta3xlwifi_socket_uid_match),
		.me = THIS_MODULE,
	},
};

static int __init gta3xlwifi_raw_uid_init(void)
{
	return xt_register_matches(gta3xlwifi_raw_uid_reg,
	                          ARRAY_SIZE(gta3xlwifi_raw_uid_reg));
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
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
int main(void){
 struct gta3xlwifi_socket_uid_match uid={0,UINT32_MAX},core={0,9999};struct xt_action_param p={&uid},c={&core};struct xt_mtchk_param check={&uid,NFPROTO_IPV4};
 T(gta3xlwifi_raw_uid_check(&check)==0);check.family=NFPROTO_IPV6;T(gta3xlwifi_raw_uid_check(&check)==0);check.family=0;T(gta3xlwifi_raw_uid_check(&check)==-EINVAL);check.family=2;current_ns=&other_ns;T(gta3xlwifi_raw_uid_check(&check)==-EINVAL);current_ns=&init_user_ns;
 uid.minimum=100;uid.maximum=99;T(gta3xlwifi_raw_uid_check(&check)==-EINVAL);uid.minimum=0;uid.maximum=UINT32_MAX;T(gta3xlwifi_raw_appid_check(&check)==-EINVAL);check.matchinfo=&core;T(gta3xlwifi_raw_appid_check(&check)==0);check.matchinfo=&uid;
 T(!gta3xlwifi_raw_uid_mt(NULL,&p)&&!gta3xlwifi_raw_appid_mt(NULL,&c));
 struct sock sk={true,10001,&initial_net};struct sk_buff skb={&sk};
 T(gta3xlwifi_raw_socket_uid(&skb)==10001);sk.full=false;T(gta3xlwifi_raw_socket_uid(&skb)==65534);sk.full=true;sk.sk_uid=UINT32_MAX;T(gta3xlwifi_raw_socket_uid(&skb)==65534);sk.sk_uid=100001;sk.net=&other_net;T(gta3xlwifi_raw_socket_uid(&skb)==1);
 // Explicit absent socket: raw UID65534 remains selectable by the denylist,
 // while the core/appId allowlist view treats it as root. No slow lookup exists.
 skb.sk=NULL;uid.minimum=uid.maximum=65534;T(gta3xlwifi_raw_uid_mt(&skb,&p));T(gta3xlwifi_raw_appid_mt(&skb,&c));
 overflowuid=20000;uid.minimum=uid.maximum=20000;T(gta3xlwifi_raw_uid_mt(&skb,&p)&&!gta3xlwifi_raw_appid_mt(&skb,&c));overflowuid=65534;
 const uint32_t values[]={0,1,9999,10000,10001,65534,65535,99999,100001,109999,110001,UINT32_MAX};
 for(unsigned context=0;context<ARRAY_SIZE(values)+2;context++)for(unsigned alternate=0;alternate<2;alternate++)for(unsigned have=0;have<2;have++)for(unsigned bits=0;bits<8;bits++){
  uint32_t expected_raw;
  sk.net=&initial_net;sk.full=true;skb.sk=&sk;
  if(context<ARRAY_SIZE(values)){sk.sk_uid=values[context];expected_raw=sk.sk_uid==UINT32_MAX?65534:sk.sk_uid;}
  else if(context==ARRAY_SIZE(values)){skb.sk=NULL;expected_raw=65534;}
  else{sk.full=false;sk.sk_uid=10001;expected_raw=65534;}
  struct __sk_buff oracle={expected_raw};present=have;entry_uid=alternate?12345:expected_raw;entry.rule=(bits&1?HAPPY_BOX_MATCH:0)|(bits&2?PENALTY_BOX_USER_MATCH:0)|(bits&4?PENALTY_BOX_ADMIN_MATCH:0);
  uid.minimum=uid.maximum=entry_uid;bool actual_match=gta3xlwifi_raw_uid_mt(&skb,&p);
  bool expected_deny=denylist_xtbpf(&oracle)!=0;bool actual_deny=actual_match&&present&&(entry.rule&(PENALTY_BOX_USER_MATCH|PENALTY_BOX_ADMIN_MATCH));assert(actual_deny==expected_deny);++comparisons;
  bool expected_allow=allowlist_xtbpf(&oracle)!=0;bool actual_allow=gta3xlwifi_raw_appid_mt(&skb,&c)||(actual_match&&present&&(entry.rule&HAPPY_BOX_MATCH));assert(actual_allow==expected_allow);++comparisons;
 }
 T(strcmp(gta3xlwifi_raw_uid_reg[0].name,"gta3xlwifi_raw_uid")==0&&strcmp(gta3xlwifi_raw_uid_reg[1].name,"gta3xlwifi_raw_appid")==0);
 T(gta3xlwifi_raw_uid_reg[0].match==gta3xlwifi_raw_uid_mt&&gta3xlwifi_raw_uid_reg[1].match==gta3xlwifi_raw_appid_mt&&gta3xlwifi_raw_uid_reg[0].hooks==((1<<1)|(1<<2)|(1<<3)));
 register_result=-ENOMEM;T(gta3xlwifi_raw_uid_init()==-ENOMEM&&registers==1);register_result=0;T(gta3xlwifi_raw_uid_init()==0&&registers==2);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
