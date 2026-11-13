
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/netfilter/gta3xlwifi_appid.h>
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define TCP_TIME_WAIT 6
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NFPROTO_UNSPEC 0
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
typedef uint32_t uid_t;
struct user_namespace{int id;};static struct user_namespace init_user_ns,other_ns;static int overflowuid=65534;static struct user_namespace* ns=&init_user_ns;
static struct user_namespace* current_user_ns(void){return ns;}
struct sock{int sk_state,refs;uid_t sk_uid;};
struct sk_buff{struct sock* sk;};struct xt_action_param{const void* matchinfo;};struct xt_mtchk_param{const void* matchinfo;unsigned family;};
static struct sock* found;static unsigned put_count,lookups;
static struct sock* skb_to_full_sk(const struct sk_buff* skb){return skb->sk;}
static struct sock* qtaguid_find_sk(const struct sk_buff* skb,struct xt_action_param* par){(void)skb;(void)par;++lookups;if(found)++found->refs;return found;}
static uid_t from_kuid_munged(struct user_namespace* n,uid_t uid){assert(n==&init_user_ns);return uid==UINT32_MAX?(uid_t)overflowuid:uid;}
static void sock_gen_put(struct sock* sk){assert(sk&&sk->refs>0);--sk->refs;++put_count;}
struct xt_match{const char* name;unsigned revision,family,hooks,matchsize;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);void* me;};
static int register_result;static unsigned registers;
static int xt_register_match(struct xt_match* m){assert(m->revision==0&&m->family==0);++registers;return register_result;}
static inline bool is_system_uid(uint32_t uid) {
    // MIN_SYSTEM_UID is AID_ROOT == 0, so uint32_t is *always* >= 0
    // MAX_SYSTEM_UID is AID_NOBODY == 9999, while AID_APP_START == 10000
    return ((uid % AID_USER_OFFSET) < AID_APP_START);
}
static bool gta3xlwifi_appid_mt(const struct sk_buff *skb,
                               struct xt_action_param *par)
{
	const struct gta3xlwifi_appid_match *info = par->matchinfo;
	struct sock *sk;
	bool referenced = false;
	uid_t uid = overflowuid;
	unsigned int appid;

	if (!skb)
		return false;
	sk = skb_to_full_sk(skb);
	if (sk && sk->sk_state == TCP_TIME_WAIT)
		sk = NULL;
	if (!sk) {
		sk = qtaguid_find_sk(skb, par);
		referenced = sk != NULL;
	}
	if (sk)
		uid = from_kuid_munged(&init_user_ns, sk->sk_uid);
	if (uid == 65534)
		uid = 0;
	appid = uid % GTA3XLWIFI_APPID_USER_OFFSET;
	if (referenced)
		sock_gen_put(sk);
	return appid >= info->minimum && appid <= info->maximum;
}
static int gta3xlwifi_appid_check(const struct xt_mtchk_param *par)
{
	const struct gta3xlwifi_appid_match *info = par->matchinfo;

	if (current_user_ns() != &init_user_ns ||
	    (par->family != NFPROTO_IPV4 && par->family != NFPROTO_IPV6) ||
	    info->minimum > info->maximum ||
	    info->maximum >= GTA3XLWIFI_APPID_USER_OFFSET)
		return -EINVAL;
	return 0;
}
static struct xt_match gta3xlwifi_appid_reg __read_mostly = {
	.name = GTA3XLWIFI_APPID_MATCH,
	.revision = 0,
	.family = NFPROTO_UNSPEC,
	.hooks = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_LOCAL_OUT),
	.match = gta3xlwifi_appid_mt,
	.checkentry = gta3xlwifi_appid_check,
	.matchsize = sizeof(struct gta3xlwifi_appid_match),
	.me = THIS_MODULE,
};

static int __init gta3xlwifi_appid_init(void)
{
	return xt_register_match(&gta3xlwifi_appid_reg);
}
static unsigned cases,comparisons;
#define C(x) do{assert(x);++cases;}while(0)
int main(void){
 struct gta3xlwifi_appid_match info={0,9999};struct xt_action_param p={&info};struct xt_mtchk_param c={&info,NFPROTO_IPV4};
 C(gta3xlwifi_appid_check(&c)==0);c.family=NFPROTO_IPV6;C(gta3xlwifi_appid_check(&c)==0);c.family=0;C(gta3xlwifi_appid_check(&c)==-EINVAL);c.family=2;
 ns=&other_ns;C(gta3xlwifi_appid_check(&c)==-EINVAL);ns=&init_user_ns;
 info.minimum=100;info.maximum=99;C(gta3xlwifi_appid_check(&c)==-EINVAL);info.minimum=0;info.maximum=100000;C(gta3xlwifi_appid_check(&c)==-EINVAL);info.maximum=UINT32_MAX;C(gta3xlwifi_appid_check(&c)==-EINVAL);info.maximum=9999;
 C(gta3xlwifi_appid_mt(NULL,&p)==false);
 struct sock direct={0,0,100001},lookup={0,0,110001};struct sk_buff skb={&direct};found=&lookup;
 C(gta3xlwifi_appid_mt(&skb,&p)&&lookups==0&&put_count==0&&lookup.refs==0);
 skb.sk=NULL;C(!gta3xlwifi_appid_mt(&skb,&p)&&lookups==1&&put_count==1&&lookup.refs==0);
 lookup.sk_uid=100001;C(gta3xlwifi_appid_mt(&skb,&p)&&put_count==2&&lookup.refs==0);
 found=NULL;C(gta3xlwifi_appid_mt(&skb,&p)&&put_count==2);
 direct.sk_state=TCP_TIME_WAIT;skb.sk=&direct;C(gta3xlwifi_appid_mt(&skb,&p)&&lookups==4&&put_count==2);direct.sk_state=0;
 for(uint32_t user=0;user<42950;user++){
  const uint32_t appids[]={0,1,9998,9999,10000,10001,65534,99999};
  for(unsigned i=0;i<sizeof(appids)/sizeof(appids[0]);i++){
   uint64_t full=(uint64_t)user*100000+appids[i];if(full>=UINT32_MAX)continue;
   direct.sk_uid=(uint32_t)full;uint32_t normalized=direct.sk_uid==65534?0:direct.sk_uid;
   bool expected=is_system_uid(normalized);assert(gta3xlwifi_appid_mt(&skb,&p)==expected);++comparisons;
  }
 }
 direct.sk_uid=UINT32_MAX;C(gta3xlwifi_appid_mt(&skb,&p));
 overflowuid=20000;skb.sk=NULL;found=NULL;C(!gta3xlwifi_appid_mt(&skb,&p));skb.sk=&direct;direct.sk_uid=UINT32_MAX;C(!gta3xlwifi_appid_mt(&skb,&p));overflowuid=65534;
 info.minimum=42;info.maximum=43;direct.sk_uid=100042;C(gta3xlwifi_appid_mt(&skb,&p));direct.sk_uid=200043;C(gta3xlwifi_appid_mt(&skb,&p));direct.sk_uid=300044;C(!gta3xlwifi_appid_mt(&skb,&p));direct.sk_uid=100041;C(!gta3xlwifi_appid_mt(&skb,&p));
 C(strcmp(gta3xlwifi_appid_reg.name,"gta3xlwifi_appid")==0);
 C(gta3xlwifi_appid_reg.match==gta3xlwifi_appid_mt&&gta3xlwifi_appid_reg.checkentry==gta3xlwifi_appid_check&&gta3xlwifi_appid_reg.matchsize==8&&gta3xlwifi_appid_reg.hooks==((1<<1)|(1<<3)));
 register_result=-ENOMEM;C(gta3xlwifi_appid_init()==-ENOMEM&&registers==1);register_result=0;C(gta3xlwifi_appid_init()==0&&registers==2);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
