#include "/srv/android/ports/lineage-24.0-arm64/kernel-runtime-policy-20261113-02/src/include/uapi/linux/netfilter/gta3xlwifi_socket_tables.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
typedef uint32_t u32;typedef uint8_t u8;
#define IS_ENABLED(x) (x)
#define CONFIG_IP6_NF_IPTABLES 1
#define __net_init
#define __net_exit
#define __init
#define THIS_MODULE NULL
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3
#define NF_ACCEPT 1
#define NF_DROP 0
#define NF_IP_PRI_FILTER 0
#define NF_IP6_PRI_FILTER 0
#define XT_STANDARD_TARGET ""
#define XT_ERROR_TARGET "ERROR"
#define XT_RETURN (-5)
#define GTA3XLWIFI_SOCKET_TABLE "g24sock"
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define late_initcall(x)
#define smp_store_release(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
#define READ_ONCE(p) __atomic_load_n(&(p),__ATOMIC_RELAXED)
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
struct xt_match{const char*name;};struct xt_target{const char*name;};
struct xt_entry_match{union{struct{struct xt_match*match;}kernel;}u;};
struct xt_entry_target{union{struct{struct xt_target*target;}kernel;}u;};
struct xt_standard_target{struct xt_entry_target target;int verdict;};
struct xt_table{char name[32];unsigned valid_hooks;void*me;u8 af;int priority;};
#define ENTRY_FIELDS unsigned match_count;struct xt_entry_match matches[4];struct xt_standard_target target
struct ipt_entry{ENTRY_FIELDS;};struct ip6t_entry{ENTRY_FIELDS;};
struct xt_table_info{void*entries;unsigned size;};
#define xt_entry_foreach(e,base,size) for((e)=(base);(char*)(e)<(char*)(base)+(size);++(e))
#define xt_ematch_foreach(m,e) for((m)=(e)->matches;(m)<(e)->matches+(e)->match_count;++(m))
static struct xt_entry_target*ipt_get_target(struct ipt_entry*e){return &e->target.target;}
static struct xt_entry_target*ip6t_get_target(struct ip6t_entry*e){return &e->target.target;}
struct ipt_standard{struct {int verdict;}target;};struct ip6t_standard{struct {int verdict;}target;};
struct ipt_replace{struct ipt_standard entries[2];};struct ip6t_replace{struct ip6t_standard entries[2];};
struct socket_tables {
    struct xt_table *v4, *v6;
};
struct net{struct socket_tables tables;void*user_ns;};static struct net net0,net1;
struct sock{bool full;unsigned sk_family;struct net*net;u32 uid;};
struct net_device{unsigned ifindex;};
struct sk_buff{unsigned char*head,*data,*network;unsigned len,data_len;struct sock*sk;struct net_device*dev;unsigned short protocol;void(*destructor)(struct sk_buff*);};
struct nf_hook_state{unsigned hook;int thresh;u8 pf;struct net_device*in,*out;struct sock*sk;struct net*net;void*hook_list;void*okfn;};
struct pernet_operations{unsigned*id;size_t size;int(*init)(struct net*);void(*exit)(struct net*);};
static unsigned alloc_calls,alloc_fail_at,allocs,frees,reg_calls,reg_fail_at,table_allocs,table_frees,eval_calls,rcu_depth,destructor_calls;
static bool held=true,privileged=true;static int reg_subsys_error;static unsigned last_hook,last_pf,last_ifindex,observed_len;static u32 observed_uid;static unsigned result_verdict=NF_ACCEPT;
static void*netpolicy_owner_file;static pthread_mutex_t netpolicy_lock=PTHREAD_MUTEX_INITIALIZER;
#define mutex_lock(m) assert(pthread_mutex_lock(m)==0)
#define mutex_unlock(m) assert(pthread_mutex_unlock(m)==0)
#define netpolicy_held held
static bool netpolicy_privileged(void){return privileged;}
static bool gta3xlwifi_netpolicy_held(void){return held;}
static void rcu_read_lock(void){++rcu_depth;}static void rcu_read_unlock(void){assert(rcu_depth);--rcu_depth;}
static void*net_generic(struct net*n,unsigned id){assert(id==7);return &n->tables;}
static bool sk_fullsock(const struct sock*s){return s->full;}static struct net*sock_net(struct sock*s){return s->net;}
static unsigned char*skb_network_header(const struct sk_buff*s){return s->network;}
static unsigned skb_headroom(const struct sk_buff*s){return s->data-s->head;}
static unsigned skb_headlen(const struct sk_buff*s){return s->len-s->data_len;}
static unsigned ip_hdrlen(const struct sk_buff*s){return (s->network[0]&15)*4;}
static void __skb_push(struct sk_buff*s,unsigned n){assert(n<=skb_headroom(s));s->data-=n;s->len+=n;}
static void __skb_pull(struct sk_buff*s,unsigned n){assert(n<=s->len);s->data+=n;s->len-=n;}
static void destructor(struct sk_buff*s){(void)s;++destructor_calls;}
static void*kalloc(size_t n){if(++alloc_calls==alloc_fail_at)return NULL;void*p=calloc(1,n);assert(p);++allocs;return p;}
static void kfree(void*p){if(p){++frees;free(p);}}
static void*ipt_alloc_initial_table(const struct xt_table*t){assert(!strcmp(t->name,"g24sock")&&t->af==2&&t->valid_hooks==10);return kalloc(sizeof(struct ipt_replace));}
static void*ip6t_alloc_initial_table(const struct xt_table*t){assert(!strcmp(t->name,"g24sock")&&t->af==10&&t->valid_hooks==10);return kalloc(sizeof(struct ip6t_replace));}
static struct xt_table*register_table(struct net*n,const struct xt_table*t){assert(n);if(++reg_calls==reg_fail_at)return (void*)(intptr_t)-EIO;struct xt_table*table=malloc(sizeof(*table));assert(table);*table=*t;++table_allocs;return table;}
static struct xt_table*ipt_register_table(struct net*n,const struct xt_table*t,const struct ipt_replace*r){assert(r->entries[0].target.verdict==-1&&r->entries[1].target.verdict==-1);return register_table(n,t);}
static struct xt_table*ip6t_register_table(struct net*n,const struct xt_table*t,const struct ip6t_replace*r){assert(r->entries[0].target.verdict==-1&&r->entries[1].target.verdict==-1);return register_table(n,t);}
static void ipt_unregister_table(struct net*n,struct xt_table*t){assert(n&&t&&!IS_ERR(t)&&t->af==2);++table_frees;free(t);}
static void ip6t_unregister_table(struct net*n,struct xt_table*t){assert(n&&t&&!IS_ERR(t)&&t->af==10);++table_frees;free(t);}
static int register_pernet_subsys(struct pernet_operations*o){assert(o->id&&o->size==sizeof(struct socket_tables));if(reg_subsys_error)return reg_subsys_error;*o->id=7;return o->init(&net0);}
static unsigned cpu_reads,bh_depth;
#define DEFINE_PER_CPU(type,name) type name
#define get_cpu_ptr(p) (++cpu_reads,(p))
#define put_cpu_ptr(p) do{(void)(p);assert(cpu_reads);--cpu_reads;}while(0)
#define this_cpu_ptr(p) (assert(bh_depth),(p))
#define local_bh_disable() do{++bh_depth;}while(0)
#define local_bh_enable() do{assert(bh_depth);--bh_depth;}while(0)
static unsigned overflowuid=65534;
static struct sock*skb_to_full_sk(const struct sk_buff*s){return s->sk;}
static u32 sock_net_uid(struct net*n,struct sock*s){assert(n==s->net);return s->uid;}
static u32 from_kuid_munged(void*n,u32 uid){(void)n;return uid;}
bool gta3xlwifi_socket_context_uid(const struct sk_buff*,u32*);
int gta3xlwifi_socket_table_policy_uid(struct sock*,struct sk_buff*,bool,u32);
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
static bool change_uid,nest;static unsigned nesting;static u32 outer_before,outer_after,inner_uid;
bool gta3xlwifi_socket_context_packet(const struct sk_buff*,bool*,bool*);
int gta3xlwifi_socket_table_policy_meta(struct sock*,struct sk_buff*,bool,u32,bool);
static bool observed_dns,observed_output;
static unsigned evaluate(struct sk_buff*s,const struct nf_hook_state*st,struct xt_table*t){assert(rcu_depth>=1&&s->sk==st->sk&&st->net==s->sk->net&&s->data==s->network&&t->af==st->pf);assert((st->hook==1&&st->in==s->dev&&!st->out)||(st->hook==3&&!st->in&&st->out==s->dev));last_hook=st->hook;last_pf=st->pf;last_ifindex=s->dev?s->dev->ifindex:0;observed_len=s->len;observed_uid=gta3xlwifi_raw_socket_uid(s);assert(bh_depth&&!cpu_reads);++eval_calls;assert(gta3xlwifi_socket_context_packet(s,&observed_dns,&observed_output));
 if(change_uid){u32 sampled=observed_uid;s->sk->uid=20002;assert(gta3xlwifi_raw_socket_uid(s)==sampled);struct sk_buff clone=*s;assert(gta3xlwifi_raw_socket_uid(&clone)==20002);}
 if(nest&&!nesting){outer_before=gta3xlwifi_raw_socket_uid(s);bool d0,o0;assert(gta3xlwifi_socket_context_packet(s,&d0,&o0));struct sk_buff clone=*s;++nesting;assert(gta3xlwifi_socket_table_policy_uid(s->sk,&clone,st->hook==3,12345)==0);--nesting;outer_after=gta3xlwifi_raw_socket_uid(s);bool d1,o1;assert(gta3xlwifi_socket_context_packet(s,&d1,&o1)&&d0==d1&&o0==o1);observed_dns=d1;observed_output=o1;assert(outer_before==outer_after);observed_uid=outer_after;}
 else if(nest)inner_uid=observed_uid;
return result_verdict;}
static unsigned ipt_do_table(struct sk_buff*s,const struct nf_hook_state*st,struct xt_table*t){assert(st->pf==2);return evaluate(s,st,t);}
static unsigned ip6t_do_table(struct sk_buff*s,const struct nf_hook_state*st,struct xt_table*t){assert(st->pf==10);return evaluate(s,st,t);}
int gta3xlwifi_socket_update_begin(const char *name)
{
    if (strcmp(name, GTA3XLWIFI_SOCKET_TABLE))
        return 0;
    if (!netpolicy_privileged())
        return -EPERM;
    mutex_lock(&netpolicy_lock);
    if (!netpolicy_owner_file || !READ_ONCE(netpolicy_held)) {
        mutex_unlock(&netpolicy_lock);
        return -EBUSY;
    }
    return 1;
}
void gta3xlwifi_socket_update_end(int held)
{
    if (held == 1)
        mutex_unlock(&netpolicy_lock);
}

static u32 gta3xlwifi_ingress_features(void){return 0;} /* registry tested separately */
#define SOCKET_HOOKS ((1U << NF_INET_LOCAL_IN) | (1U << NF_INET_LOCAL_OUT))

static unsigned int socket_tables_id;
static bool socket_tables_registered;
static const struct xt_table socket_table4 = {
    .name = GTA3XLWIFI_SOCKET_TABLE, .valid_hooks = SOCKET_HOOKS,
    .me = THIS_MODULE, .af = NFPROTO_IPV4, .priority = NF_IP_PRI_FILTER,
};
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
static const struct xt_table socket_table6 = {
    .name = GTA3XLWIFI_SOCKET_TABLE, .valid_hooks = SOCKET_HOOKS,
    .me = THIS_MODULE, .af = NFPROTO_IPV6, .priority = NF_IP6_PRI_FILTER,
};
#endif
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
static bool socket_target_safe(const struct xt_entry_target *target)
{
    const char *name = target->u.kernel.target->name;
    if (!strcmp(name, XT_ERROR_TARGET))
        return true; /* Chain-label/terminal ERROR can only DROP, never steal. */
    if (strcmp(name, XT_STANDARD_TARGET))
        return false;
    /* Core translation already checked jump offsets/loop freedom. Restrict
     * verdicts to non-consuming ACCEPT/DROP/RETURN or validated chain jumps.
     */
    return ((const struct xt_standard_target *)target)->verdict >= 0 ||
           ((const struct xt_standard_target *)target)->verdict == XT_RETURN ||
           ((const struct xt_standard_target *)target)->verdict == -NF_ACCEPT - 1 ||
           ((const struct xt_standard_target *)target)->verdict == -NF_DROP - 1;
}
int gta3xlwifi_socket_rules4(const char *name, const struct xt_table_info *info)
{
    struct ipt_entry *entry;
    struct xt_entry_match *match;
    if (strcmp(name, GTA3XLWIFI_SOCKET_TABLE))
        return 0;
    xt_entry_foreach(entry, info->entries, info->size) {
        xt_ematch_foreach(match, entry)
            if (!socket_match_safe(match))
                return -EINVAL;
        if (!socket_target_safe(ipt_get_target(entry)))
            return -EINVAL;
    }
    return 0;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_socket_rules4);
int gta3xlwifi_socket_rules6(const char *name, const struct xt_table_info *info)
{
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    struct ip6t_entry *entry;
    struct xt_entry_match *match;
    if (strcmp(name, GTA3XLWIFI_SOCKET_TABLE))
        return 0;
    xt_entry_foreach(entry, info->entries, info->size) {
        xt_ematch_foreach(match, entry)
            if (!socket_match_safe(match))
                return -EINVAL;
        if (!socket_target_safe(ip6t_get_target(entry)))
            return -EINVAL;
    }
    return 0;
#else
    return strcmp(name, GTA3XLWIFI_SOCKET_TABLE) ? 0 : -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL_GPL(gta3xlwifi_socket_rules6);
static int __net_init socket_tables_net_init(struct net *net)
{
    struct socket_tables *tables = net_generic(net, socket_tables_id);
    struct ipt_replace *v4;
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    struct ip6t_replace *v6;
#endif
    v4 = ipt_alloc_initial_table(&socket_table4);
    if (!v4)
        return -ENOMEM;
    ((struct ipt_standard *)v4->entries)[0].target.verdict = -NF_DROP - 1;
    ((struct ipt_standard *)v4->entries)[1].target.verdict = -NF_DROP - 1;
    tables->v4 = ipt_register_table(net, &socket_table4, v4);
    kfree(v4);
    if (IS_ERR(tables->v4)) {
        int result = PTR_ERR(tables->v4);
        tables->v4 = NULL;
        return result;
    }
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    v6 = ip6t_alloc_initial_table(&socket_table6);
    if (!v6) {
        ipt_unregister_table(net, tables->v4);
        tables->v4 = NULL;
        return -ENOMEM;
    }
    ((struct ip6t_standard *)v6->entries)[0].target.verdict = -NF_DROP - 1;
    ((struct ip6t_standard *)v6->entries)[1].target.verdict = -NF_DROP - 1;
    tables->v6 = ip6t_register_table(net, &socket_table6, v6);
    kfree(v6);
    if (IS_ERR(tables->v6)) {
        int result = PTR_ERR(tables->v6);
        tables->v6 = NULL;
        ipt_unregister_table(net, tables->v4);
        tables->v4 = NULL;
        return result;
    }
#endif
    return 0;
}
static void __net_exit socket_tables_net_exit(struct net *net)
{
    struct socket_tables *tables = net_generic(net, socket_tables_id);
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    if (tables->v6)
        ip6t_unregister_table(net, tables->v6);
#endif
    if (tables->v4)
        ipt_unregister_table(net, tables->v4);
    tables->v4 = tables->v6 = NULL;
}
static struct pernet_operations socket_tables_ops = {
    .id = &socket_tables_id, .size = sizeof(struct socket_tables),
    .init = socket_tables_net_init, .exit = socket_tables_net_exit,
};
static int __init socket_tables_init(void)
{
    /* Intentionally no xt_hook_link()/NF hook registration. */
    int result = register_pernet_subsys(&socket_tables_ops);
    if (!result)
        smp_store_release(&socket_tables_registered, true);
    return result;
}
/* qtaguid is bool. Initialize after both ip_tables modules registered their
 * standard/ERROR targets, rather than relying on net/ directory link order. */
late_initcall(socket_tables_init);
/* A capability for this exact primitive only. Both families and the per-netns
 * late registration must be real; no packet hook/backend-ready claim is made.
 */
u32 gta3xlwifi_socket_tables_features(void)
{
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    return smp_load_acquire(&socket_tables_registered) ?
        (GTA3XLWIFI_UID_CAP_SOCKET_TABLES | gta3xlwifi_ingress_features()) : 0;
#else
    return 0;
#endif
}
EXPORT_SYMBOL_GPL(gta3xlwifi_socket_tables_features);
struct socket_uid_snapshot {
    const struct sk_buff *skb;
    u32 uid;
    bool system_dns, output;
};
static DEFINE_PER_CPU(struct socket_uid_snapshot, socket_uid_context);
bool gta3xlwifi_socket_context_uid(const struct sk_buff *skb, u32 *uid)
{
    struct socket_uid_snapshot *context;
    bool found;
    if (!skb || !uid)
        return false;
    context = get_cpu_ptr(&socket_uid_context);
    found = context->skb == skb;
    if (found)
        *uid = context->uid;
    put_cpu_ptr(&socket_uid_context);
    return found;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_socket_context_uid);
bool gta3xlwifi_socket_context_packet(const struct sk_buff *skb, bool *dns, bool *output)
{
    struct socket_uid_snapshot *context;
    bool found;
    if (!skb || !dns || !output)
        return false;
    context = get_cpu_ptr(&socket_uid_context);
    found = context->skb == skb;
    if (found) {
        *dns = context->system_dns;
        *output = context->output;
    }
    put_cpu_ptr(&socket_uid_context);
    return found;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_socket_context_packet);
int gta3xlwifi_socket_table_policy_meta(struct sock *sk, struct sk_buff *skb,
                                       bool output, u32 uid_snapshot, bool system_dns)
{
    struct socket_tables *tables;
    struct xt_table *table;
    struct nf_hook_state state = {};
    struct sock *saved_sk;
    struct socket_uid_snapshot *context, previous;
    unsigned int verdict, offset;
    int result = 0;
    if (!sk || !skb || !sk_fullsock(sk) ||
        (sk->sk_family != AF_INET && sk->sk_family != AF_INET6))
        return 0;
    /* Selected socket stages have L3 at or before data, as modern cgroup skb
     * evaluation does. Reject inconsistent header metadata before mutation.
     */
    if (!smp_load_acquire(&socket_tables_registered))
        return -EPERM;
    if (skb_network_header(skb) > skb->data)
        return -EPERM;
    offset = skb->data - skb_network_header(skb);
    if (offset > skb_headroom(skb))
        return -EPERM;
    rcu_read_lock();
    if (gta3xlwifi_netpolicy_held()) {
        result = -EPERM;
        goto out;
    }
    state.net = sock_net(sk);
    tables = net_generic(state.net, socket_tables_id);
    /* Choose packet family (IPv4-mapped AF_INET6 sockets can carry IPv4). */
    if (skb->protocol == htons(ETH_P_IP)) {
        state.pf = NFPROTO_IPV4;
        table = tables->v4;
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        state.pf = NFPROTO_IPV6;
        table = tables->v6;
    } else {
        result = -EPERM;
        goto out;
    }
    if (!table || skb_headlen(skb) + offset <
            (state.pf == NFPROTO_IPV4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr)) ||
        (state.pf == NFPROTO_IPV4 && ip_hdrlen(skb) < sizeof(struct iphdr))) {
        result = -EPERM;
        goto out;
    }
    state.hook = output ? NF_INET_LOCAL_OUT : NF_INET_LOCAL_IN;
    state.in = output ? NULL : skb->dev;
    state.out = output ? skb->dev : NULL;
    state.sk = sk;
    /* Bottom halves/preemption stay disabled across the entire synchronous
     * read-only evaluation, including nested ipt_do_table. A nested evaluation
     * saves/restores the prior context, and pointer identity isolates clones.
     */
    local_bh_disable();
    context = this_cpu_ptr(&socket_uid_context);
    previous = *context;
    context->skb = skb;
    context->uid = uid_snapshot == 65534 ? 0 : uid_snapshot;
    context->system_dns = system_dns;
    context->output = output;
    saved_sk = skb->sk;
    skb->sk = sk;
    __skb_push(skb, offset);
    if (state.pf == NFPROTO_IPV4)
        verdict = ipt_do_table(skb, &state, table);
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    else
        verdict = ip6t_do_table(skb, &state, table);
#else
    else
        verdict = NF_DROP;
#endif
    __skb_pull(skb, offset);
    skb->sk = saved_sk;
    *context = previous;
    local_bh_enable();
    if (verdict != NF_ACCEPT)
        result = -EPERM;
out:
    rcu_read_unlock();
    return result;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_socket_table_policy_meta);
/* No tag query is invented by these compatibility entry points. Only actual
 * socket hooks call policy_meta with their authoritative system-DNS sample. */
int gta3xlwifi_socket_table_policy_uid(struct sock *sk, struct sk_buff *skb,
                                      bool output, u32 uid_snapshot)
{
    return gta3xlwifi_socket_table_policy_meta(sk, skb, output, uid_snapshot, false);
}
EXPORT_SYMBOL_GPL(gta3xlwifi_socket_table_policy_uid);
int gta3xlwifi_socket_table_policy(struct sock *sk, struct sk_buff *skb, bool output)
{
    struct net *net;
    u32 uid;
    int result;
    if (!sk || !skb || !sk_fullsock(sk) ||
        (sk->sk_family != AF_INET && sk->sk_family != AF_INET6))
        return 0;
    rcu_read_lock();
    if (gta3xlwifi_netpolicy_held()) {
        result = -EPERM;
        goto out;
    }
    net = sock_net(sk);
    uid = from_kuid_munged(net->user_ns, sock_net_uid(net, sk));
    result = gta3xlwifi_socket_table_policy_uid(sk, skb, output, uid);
out:
    rcu_read_unlock();
    return result;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_socket_table_policy);

static unsigned cases,comparisons;
#define T(x) do{++cases;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}}while(0)
static void reset(void){assert(allocs==frees&&table_allocs==table_frees);memset(&net0,0,sizeof(net0));memset(&net1,0,sizeof(net1));alloc_calls=alloc_fail_at=reg_calls=reg_fail_at=0;reg_subsys_error=0;socket_tables_registered=false;held=true;privileged=true;netpolicy_owner_file=NULL;}
int main(void){
 reset();T(gta3xlwifi_socket_tables_features()==0);reg_subsys_error=-EIO;T(socket_tables_init()==-EIO&&!socket_tables_registered);T(gta3xlwifi_socket_tables_features()==0);
 for(unsigned fail=1;fail<=2;fail++){reset();alloc_fail_at=fail;T(socket_tables_init()==-ENOMEM&&!socket_tables_registered&&allocs==frees&&table_allocs==table_frees&&!net0.tables.v4&&!net0.tables.v6);reset();reg_fail_at=fail;T(socket_tables_init()==-EIO&&!socket_tables_registered&&allocs==frees&&table_allocs==table_frees&&!net0.tables.v4&&!net0.tables.v6);}
 reset();T(socket_tables_init()==0&&socket_tables_registered&&net0.tables.v4&&net0.tables.v6);T(gta3xlwifi_socket_tables_features()==256);T(socket_tables_net_init(&net1)==0&&net1.tables.v4&&net1.tables.v6&&net1.tables.v4!=net0.tables.v4);
 // Real whitelist helpers, using already-translated target/match fixture layouts.
 struct xt_target standard={""},error={"ERROR"},reject={"REJECT"},queue={"NFQUEUE"};struct xt_match matches[]={{"gta3xlwifi_raw_uid"},{"gta3xlwifi_raw_appid"},{"gta3xlwifi_owner_skip"},{"gta3xlwifi_non_loopback"},{"owner"},{"gta3xlwifi_raw_uidX"}};
 struct ipt_entry e4={0};struct ip6t_entry e6={0};struct xt_table_info i4={&e4,sizeof(e4)},i6={&e6,sizeof(e6)};
 for(unsigned family=0;family<2;family++)for(unsigned target=0;target<4;target++)for(int verdict=-8;verdict<10;verdict++)for(unsigned match=0;match<6;match++){
  struct xt_target*t=target==0?&standard:target==1?&error:target==2?&reject:&queue;e4.match_count=e6.match_count=1;e4.matches[0].u.kernel.match=e6.matches[0].u.kernel.match=&matches[match];e4.target.target.u.kernel.target=e6.target.target.u.kernel.target=t;e4.target.verdict=e6.target.verdict=verdict;
  bool allowed=match<4&&(target==1||(target==0&&(verdict>=0||verdict==-1||verdict==-2||verdict==-5)));
  int actual=family?gta3xlwifi_socket_rules6("g24sock",&i6):gta3xlwifi_socket_rules4("g24sock",&i4);assert(actual==(allowed?0:-EINVAL));assert((family?gta3xlwifi_socket_rules6("filter",&i6):gta3xlwifi_socket_rules4("filter",&i4))==0);++comparisons;
 }
 T(comparisons==864);T(gta3xlwifi_socket_update_begin("filter")==0);privileged=false;T(gta3xlwifi_socket_update_begin("g24sock")==-EPERM);privileged=true;T(gta3xlwifi_socket_update_begin("g24sock")==-EBUSY);netpolicy_owner_file=&net0;held=false;T(gta3xlwifi_socket_update_begin("g24sock")==-EBUSY);held=true;T(gta3xlwifi_socket_update_begin("g24sock")==1);T(pthread_mutex_trylock(&netpolicy_lock)==EBUSY);gta3xlwifi_socket_update_end(0);T(pthread_mutex_trylock(&netpolicy_lock)==EBUSY);gta3xlwifi_socket_update_end(1);T(pthread_mutex_trylock(&netpolicy_lock)==0);T(pthread_mutex_unlock(&netpolicy_lock)==0);
 unsigned char bytes[256]={0};struct net_device dev={17};struct sock owner={true,AF_INET,&net1,10001},foreign={true,AF_INET,&net0,0};
 struct sk_buff skb={bytes,bytes+34,bytes+14,180,0,&foreign,&dev,htons(ETH_P_IP),destructor};bytes[14]=0x45;
 struct sk_buff saved=skb;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&!memcmp(&skb,&saved,sizeof(skb))&&eval_calls==0);held=false;
 for(unsigned family=0;family<2;family++)for(unsigned direction=0;direction<2;direction++)for(unsigned verdict=0;verdict<6;verdict++){
  skb.protocol=htons(family?ETH_P_IPV6:ETH_P_IP);bytes[14]=family?0x60:0x45;saved=skb;result_verdict=verdict;unsigned before=eval_calls;
  T(gta3xlwifi_socket_table_policy(&owner,&skb,direction)==(verdict==NF_ACCEPT?0:-EPERM)&&eval_calls==before+1&&!memcmp(&skb,&saved,sizeof(skb))&&last_pf==(family?10:2)&&last_hook==(direction?3:1)&&observed_uid==10001&&observed_len==200&&last_ifindex==17&&!destructor_calls&&!rcu_depth);
 }
 // IPv4 carried by AF_INET6 still selects packet-family4; inode UID changes are honored.
 owner.sk_family=AF_INET6;owner.uid=10002;skb.protocol=htons(ETH_P_IP);bytes[14]=0x45;result_verdict=NF_ACCEPT;saved=skb;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==0&&observed_uid==10002&&last_pf==2&&!memcmp(&skb,&saved,sizeof(skb)));
 unsigned before=eval_calls;T(gta3xlwifi_socket_table_policy(NULL,&skb,false)==0);owner.full=false;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==0);owner.full=true;owner.sk_family=AF_UNIX;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==0&&eval_calls==before);owner.sk_family=AF_INET;
 skb.network=skb.data+1;saved=skb;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&!memcmp(&skb,&saved,sizeof(skb)));skb.network=bytes+14;skb.len=0;skb.data_len=0;skb.data=bytes+14;saved=skb;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&!memcmp(&skb,&saved,sizeof(skb))&&eval_calls==before);
 skb=saved;skb.len=200;bytes[14]=0x44;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&eval_calls==before);bytes[14]=0x45;skb.protocol=0;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&eval_calls==before);skb.protocol=htons(ETH_P_IP);struct xt_table*old=net1.tables.v4;net1.tables.v4=NULL;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&eval_calls==before);net1.tables.v4=old;

 // The actual raw getter is scoped to this skb and returns one normalized sample.
 skb=(struct sk_buff){bytes,bytes+34,bytes+14,180,0,&foreign,&dev,htons(ETH_P_IP),destructor};bytes[14]=0x45;owner.uid=10001;owner.full=true;owner.sk_family=AF_INET;held=false;result_verdict=NF_ACCEPT;
 change_uid=true;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==0&&observed_uid==10001&&owner.uid==20002&&!bh_depth&&!cpu_reads);change_uid=false;
 u32 sampled=777;T(!gta3xlwifi_socket_context_uid(&skb,&sampled)&&sampled==777);T(!gta3xlwifi_socket_context_uid(NULL,&sampled)&&sampled==777);T(!gta3xlwifi_socket_context_uid(&skb,NULL));
 owner.uid=65534;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==0&&observed_uid==0);skb.sk=&owner;T(gta3xlwifi_raw_socket_uid(&skb)==65534);skb.sk=&foreign;
 owner.uid=20001;T(gta3xlwifi_socket_table_policy_uid(&owner,&skb,false,10001)==0&&observed_uid==10001&&owner.uid==20001);
 nest=true;T(gta3xlwifi_socket_table_policy_uid(&owner,&skb,false,10001)==0&&outer_before==10001&&inner_uid==12345&&outer_after==10001&&!cpu_reads&&!bh_depth);nest=false;
 T(!gta3xlwifi_socket_context_uid(&skb,&sampled)&&sampled==777&&gta3xlwifi_raw_socket_uid(&skb)==0);
 
 bool dns=true,direction=false;T(!gta3xlwifi_socket_context_packet(&skb,&dns,&direction)&&dns&&!direction);T(!gta3xlwifi_socket_context_packet(NULL,&dns,&direction)&&dns&&!direction);T(!gta3xlwifi_socket_context_packet(&skb,NULL,&direction));T(!gta3xlwifi_socket_context_packet(&skb,&dns,NULL));
 T(gta3xlwifi_socket_table_policy_meta(&owner,&skb,true,10001,true)==0&&observed_uid==10001&&observed_dns&&observed_output);
 T(gta3xlwifi_socket_table_policy_uid(&owner,&skb,false,10001)==0&&!observed_dns&&!observed_output);
 nest=true;T(gta3xlwifi_socket_table_policy_meta(&owner,&skb,false,10001,true)==0&&observed_dns&&!observed_output&&outer_before==10001&&outer_after==10001&&inner_uid==12345);nest=false;
 T(!gta3xlwifi_socket_context_packet(&skb,&dns,&direction)&&dns&&!direction&&!bh_depth&&!cpu_reads);
 socket_tables_net_exit(&net1);socket_tables_net_exit(&net0);socket_tables_registered=false;T(gta3xlwifi_socket_tables_features()==0);T(allocs==frees&&table_allocs==table_frees&&!net0.tables.v4&&!net0.tables.v6&&!net1.tables.v4&&!net1.tables.v6&&!destructor_calls&&!rcu_depth);
 printf("passed_cases=%u grammar_comparisons=%u\n",cases,comparisons);return 0;
}
