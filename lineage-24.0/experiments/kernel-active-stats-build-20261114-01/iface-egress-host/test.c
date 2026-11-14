
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
typedef uint32_t u32;typedef uint64_t u64;
#define __user
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define EXPORT_SYMBOL_GPL(x)
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define DEFINE_SPINLOCK(x) pthread_mutex_t x=PTHREAD_MUTEX_INITIALIZER
#define spin_lock_bh(x) assert(pthread_mutex_lock(x)==0)
#define spin_unlock_bh(x) assert(pthread_mutex_unlock(x)==0)
struct net{const void*user_ns;};struct sock{struct net*net;u32 uid;bool full;};
struct net_device;struct sk_buff{u32 len;uint16_t protocol;struct sock*sk;struct net_device*dev;};
static u32 hash_32(u32 key,unsigned bits){return (key*0x9e370001U)>>(32-bits);}
static unsigned from_calls,to_calls,from_fault,to_fault,allocs,frees;static bool alloc_fault;static void(*copy_hook)(size_t);
static int copy_from_user(void*d,const void*s,size_t n){if(++from_calls==from_fault||!s)return 1;memcpy(d,s,n);return 0;}
static int copy_to_user(void*d,const void*s,size_t n){if(++to_calls==to_fault||!d)return 1;if(copy_hook)copy_hook(n);memcpy(d,s,n);return 0;}
static void*vzalloc(size_t n){if(alloc_fault)return NULL;void*p=calloc(1,n);if(p)++allocs;return p;}
static void vfree(void*p){if(p){++frees;free(p);}}
static void sort(void*p,size_t n,size_t size,int(*cmp)(const void*,const void*),void*swap){assert(!swap);qsort(p,n,size,cmp);}
u32 gta3xlwifi_iface_stats_features(void);
#define IFACE_HASH_BITS 11
#define IFACE_BUCKETS (1U << IFACE_HASH_BITS)
struct iface_counter {
    u32 next, ifindex;
    u64 rx_packets,rx_bytes,tx_packets,tx_bytes;
};
static DEFINE_SPINLOCK(iface_lock);
/* Index+1 links, no allocation in packet context and no external pointers. */
static u32 iface_heads[IFACE_BUCKETS],iface_count;
static struct iface_counter iface_rows[GTA3XLWIFI_IFACE_STATS_MAX];
static u64 iface_lost_updates,iface_sequence;
static void iface_amount(const struct sk_buff *skb,u64 *packets,u64 *bytes)
{
    /* EXACT A17 interface XT program's explicit KVER_4_9 arithmetic. This is
     * not a claim that the real4.4 kernel is5.x or that it loaded a BPF program.
     * UID/tag accounting uses different modern GSO semantics and is separate.
     */
    const int mtu=1500;
    u64 p=1,b=skb->len;
    if(b>mtu){
        int overhead=(skb->protocol==htons(ETH_P_IPV6)?sizeof(struct ipv6hdr):sizeof(struct iphdr))+32;
        int mss=mtu-overhead;
        u64 payload=b-overhead;
        p=(payload+mss-1)/mss;b=overhead*p+payload;
    }
    *packets=p;*bytes=b;
}
void gta3xlwifi_iface_lost(void)
{
    spin_lock_bh(&iface_lock);
    if(iface_lost_updates!=~(u64)0)++iface_lost_updates;
    ++iface_sequence;
    spin_unlock_bh(&iface_lock);
}
EXPORT_SYMBOL_GPL(gta3xlwifi_iface_lost);
int gta3xlwifi_iface_account(const struct sk_buff *skb,u32 ifindex,bool output,bool undo)
{
    struct iface_counter *row=NULL;
    u32 bucket,index;
    u64 packets,bytes;
    if(!skb)return -EINVAL;
    iface_amount(skb,&packets,&bytes);
    if(undo){packets=-packets;bytes=-bytes;} /* Exact unsigned A17 UNDO. */
    bucket=hash_32(ifindex,IFACE_HASH_BITS);
    spin_lock_bh(&iface_lock);
    for(index=iface_heads[bucket];index;index=iface_rows[index-1].next)
        if(iface_rows[index-1].ifindex==ifindex){row=&iface_rows[index-1];break;}
    if(!row){
        if(iface_count==GTA3XLWIFI_IFACE_STATS_MAX){
            if(iface_lost_updates!=~(u64)0)++iface_lost_updates;
            ++iface_sequence;spin_unlock_bh(&iface_lock);return -ENOSPC;
        }
        row=&iface_rows[iface_count++];row->ifindex=ifindex;
        row->next=iface_heads[bucket];iface_heads[bucket]=iface_count;
    }
    if(output){row->tx_packets+=packets;row->tx_bytes+=bytes;}
    else{row->rx_packets+=packets;row->rx_bytes+=bytes;}
    ++iface_sequence;spin_unlock_bh(&iface_lock);return 0;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_iface_account);
static int iface_compare(const void *a,const void *b)
{
    const struct gta3xlwifi_iface_stats_entry *x=a,*y=b;
    return x->ifindex<y->ifindex?-1:x->ifindex>y->ifindex?1:0;
}
long gta3xlwifi_iface_stats_ioctl(unsigned int cmd,unsigned long arg)
{
    struct gta3xlwifi_iface_stats_transfer request,answer;
    struct gta3xlwifi_iface_stats_entry *rows=NULL;
    u32 i;
    int result=0;
    if(cmd!=GTA3XLWIFI_IFACE_STATS_GET)return -ENOTTY;
    if(!arg)return -EFAULT;
    if(!gta3xlwifi_iface_stats_features())return -EOPNOTSUPP;
    if(copy_from_user(&request,(void __user *)arg,sizeof(request)))return -EFAULT;
    if(request.version!=GTA3XLWIFI_IFACE_STATS_VERSION||
       request.count>GTA3XLWIFI_IFACE_STATS_MAX||
       (!!request.count!=!!request.entries)||request.lost_updates||request.update_sequence)return -EINVAL;
    if(request.count){rows=vzalloc(request.count*sizeof(*rows));if(!rows)return -ENOMEM;}
    answer=request;
    spin_lock_bh(&iface_lock);
    answer.count=iface_count;answer.lost_updates=iface_lost_updates;answer.update_sequence=iface_sequence;
    if(request.count&&request.count<iface_count)result=-ENOSPC;
    else if(request.count)for(i=0;i<iface_count;++i){
        rows[i].ifindex=iface_rows[i].ifindex;
        rows[i].rx_packets=iface_rows[i].rx_packets;rows[i].rx_bytes=iface_rows[i].rx_bytes;
        rows[i].tx_packets=iface_rows[i].tx_packets;rows[i].tx_bytes=iface_rows[i].tx_bytes;
    }
    spin_unlock_bh(&iface_lock);
    if(!result&&request.count){
        sort(rows,answer.count,sizeof(*rows),iface_compare,NULL);
        if(copy_to_user((void __user *)(unsigned long)request.entries,rows,answer.count*sizeof(*rows)))result=-EFAULT;
    }
    if(!result&&copy_to_user((void __user *)arg,&answer,sizeof(answer)))result=-EFAULT;
    vfree(rows);return result;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_iface_stats_ioctl);

#define NF_INET_PRE_ROUTING 0
#define NF_INET_POST_ROUTING 4
#define NFPROTO_UNSPEC 0
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
struct net_device{u32 ifindex;};
struct xt_action_param{const void*matchinfo;const struct net_device*in,*out;};
struct xt_mtchk_param{const char*table;unsigned family,hook_mask;const void*matchinfo;};
struct xt_match{const char*name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void*me;};
static int init_user_ns;static const void*user_ns=&init_user_ns;
static const void*current_user_ns(void){return user_ns;}
static struct sock*skb_to_full_sk(const struct sk_buff*s){return s->sk&&s->sk->full?s->sk:NULL;}
static bool sk_fullsock(const struct sock*s){return s->full;}
static struct net*sock_net(struct sock*s){return s->net;}
static u32 sock_net_uid(struct net*n,struct sock*s){assert(n==s->net);return s->uid;}
static u32 from_kuid_munged(const void*n,u32 uid){assert(n==&init_user_ns);return uid;}
static int metadata_result=-ENOENT;static u32 stats_uid,tag;static unsigned metadata_calls;
static int gta3xlwifi_socket_accounting(const struct sock*s,u32*u,u32*t){assert(s);++metadata_calls;if(metadata_result)return metadata_result;*u=stats_uid;*t=tag;return 0;}
static int reg_error;static unsigned registers;static int xt_register_match(struct xt_match*);
static bool gta3xlwifi_iface_registered;

u32 gta3xlwifi_iface_stats_features(void)
{
    return READ_ONCE(gta3xlwifi_iface_registered)?GTA3XLWIFI_UID_CAP_IFACE_STATS:0;
}

static bool gta3xlwifi_iface_mt(const struct sk_buff *skb,struct xt_action_param *par)
{
    const struct gta3xlwifi_iface_stats_match *info=par->matchinfo;
    const struct net_device *device=info->output?par->out:par->in;
    if(info->output){
        struct sock *sk=skb_to_full_sk(skb);
        if(sk&&sk_fullsock(sk)){
            struct net *net=sock_net(sk);
            u32 uid=from_kuid_munged(net->user_ns,sock_net_uid(net,sk));
            if(uid==1000){
                u32 stats_uid,tag;
                int metadata=gta3xlwifi_socket_accounting(sk,&stats_uid,&tag);
                if(!metadata&&stats_uid==1029)return false; /* Exact A17 CLAT NOMATCH. */
                if(metadata&&metadata!=-ENOENT){gta3xlwifi_iface_lost();return false;}
            }
        }
    }
    gta3xlwifi_iface_account(skb,device?device->ifindex:0,info->output,false);
    return true; /* Counter effect only, never consumes/drops a packet. */
}

static int gta3xlwifi_iface_check(const struct xt_mtchk_param *par)
{
    const struct gta3xlwifi_iface_stats_match *info=par->matchinfo;
    unsigned int hook;
    if(current_user_ns()!=&init_user_ns||info->reserved||info->output>1||
       (par->family!=NFPROTO_IPV4&&par->family!=NFPROTO_IPV6))return -EINVAL;
    hook=info->output?NF_INET_POST_ROUTING:NF_INET_PRE_ROUTING;
    if(strcmp(par->table,info->output?"mangle":"raw")||par->hook_mask&~(1U<<hook))return -EINVAL;
    return 0;
}
static struct xt_match gta3xlwifi_iface_reg __read_mostly={
    .name=GTA3XLWIFI_IFACE_STATS_MATCH,.revision=0,.family=NFPROTO_UNSPEC,
    .hooks=(1<<NF_INET_PRE_ROUTING)|(1<<NF_INET_POST_ROUTING),
    .match=gta3xlwifi_iface_mt,.checkentry=gta3xlwifi_iface_check,
    .matchsize=sizeof(struct gta3xlwifi_iface_stats_match),.me=THIS_MODULE,
};
static int __init gta3xlwifi_iface_init(void)
{
    int result=xt_register_match(&gta3xlwifi_iface_reg);
    if(!result)WRITE_ONCE(gta3xlwifi_iface_registered,true);
    return result;
}

static int xt_register_match(struct xt_match*m){assert(m==&gta3xlwifi_iface_reg);++registers;return reg_error;}
#define function static
#define KVER_IS_AT_LEAST(k,a,b) ((k).version>=(((a)<<16)|((b)<<8)))
#define BPF_NOEXIST 1
struct kver_uint{unsigned version;};struct egress_bool{bool egress;};struct undo_bool{bool undo;};
struct bpf_sock{u32 protocol;};struct __sk_buff{u32 len;uint16_t protocol;u32 gso_segs;struct bpf_sock*sk;};
typedef struct{u64 rxPackets,rxBytes,txPackets,txBytes;}StatsValue;
static StatsValue oracle_value;
static StatsValue*bpf_iface_stats_map_lookup_elem(const u32*key){assert(!*key);return &oracle_value;}
static void bpf_iface_stats_map_update_elem(const u32*k,StatsValue*v,unsigned flags){(void)k;(void)v;assert(flags==BPF_NOEXIST);}
static struct bpf_sock*bpf_sk_fullsock(struct bpf_sock*s){return s;}
#define DEFINE_UPDATE_STATS(the_stats_map, TypeOfKey)                                            \
    function void update_##the_stats_map(const struct __sk_buff* const skb,                      \
                                         const TypeOfKey* const key,                             \
                                         const struct egress_bool egress,                        \
                                         const struct kver_uint kver,                            \
                                         const struct undo_bool undo) {                          \
        StatsValue* value = bpf_##the_stats_map##_lookup_elem(key);                              \
        if (!value) {                                                                            \
            StatsValue newValue = {};                                                            \
            bpf_##the_stats_map##_update_elem(key, &newValue, BPF_NOEXIST);                      \
            value = bpf_##the_stats_map##_lookup_elem(key);                                      \
        }                                                                                        \
        if (value) {                                                                             \
            const bool is5_4 = KVER_IS_AT_LEAST(kver, 5, 4);                                     \
            const int mtu = 1500;                                                                \
            uint64_t packets = 1;                                                                \
            uint64_t bytes = skb->len;                                                           \
            volatile uint32_t gso_segs = is5_4 ? skb->gso_segs : 1;                              \
            if ((!is5_4 && bytes > mtu) || (is5_4 && gso_segs > 1)) {                            \
                const bool is_ipv6 = (skb->protocol == htons(ETH_P_IPV6));                       \
                const int ip_overhead = is_ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr); \
                struct bpf_sock * const sk = is5_4 && skb->sk ? bpf_sk_fullsock(skb->sk) : NULL; \
                const bool is_tcp_or_unknown = !sk || sk->protocol == IPPROTO_TCP;               \
                const int tcphdr_size = sizeof(struct tcphdr);                                   \
                const int udphdr_size = sizeof(struct udphdr);                                   \
                const int L4_size = is_tcp_or_unknown ? tcphdr_size + 12 : udphdr_size;          \
                const int overhead = ip_overhead + L4_size;                                      \
                const int mss = mtu - overhead;                                                  \
                const uint64_t payload = bytes - overhead;                                       \
                packets = is5_4 ? gso_segs : (payload + mss - 1) / mss;                          \
                bytes = overhead * packets + payload;                                            \
            }                                                                                    \
            if (undo.undo) {                                                                     \
                packets = -packets;                                                              \
                bytes = -bytes;                                                                  \
            }                                                                                    \
            if (egress.egress) {                                                                 \
                __sync_fetch_and_add(&value->txPackets, packets);                                \
                __sync_fetch_and_add(&value->txBytes, bytes);                                    \
            } else {                                                                             \
                __sync_fetch_and_add(&value->rxPackets, packets);                                \
                __sync_fetch_and_add(&value->rxBytes, bytes);                                    \
            }                                                                                    \
        }                                                                                        \
    }


DEFINE_UPDATE_STATS(iface_stats_map,uint32_t)

static unsigned cases;
#define T(x) do{assert(x);++cases;}while(0)
static void reset_store(void){memset(iface_heads,0,sizeof(iface_heads));memset(iface_rows,0,sizeof(iface_rows));iface_count=0;iface_lost_updates=iface_sequence=0;from_calls=to_calls=from_fault=to_fault=0;alloc_fault=false;copy_hook=NULL;metadata_result=-ENOENT;metadata_calls=0;}
static long snap(struct gta3xlwifi_iface_stats_transfer*t){return gta3xlwifi_iface_stats_ioctl(GTA3XLWIFI_IFACE_STATS_GET,(unsigned long)t);}
static struct gta3xlwifi_iface_stats_transfer request(void*p,unsigned count){return(struct gta3xlwifi_iface_stats_transfer){1,count,(uintptr_t)p,0,0};}
static struct sk_buff packet={64,0,NULL};
static void*producer(void*arg){u32 id=(uintptr_t)arg;for(unsigned i=0;i<10000;i++)assert(gta3xlwifi_iface_account(&packet,id,i&1,false)==0);return NULL;}
static void during_copy(size_t n){if(n>sizeof(struct gta3xlwifi_iface_stats_transfer)){copy_hook=NULL;assert(gta3xlwifi_iface_account(&packet,17,true,false)==0);}}

static pthread_mutex_t rcu_mu=PTHREAD_MUTEX_INITIALIZER,decision_mu=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rcu_cv=PTHREAD_COND_INITIALIZER,decision_cv=PTHREAD_COND_INITIALIZER;
static __thread unsigned read_depth;
static unsigned readers;static bool hold_entered,held,pause_decision,decision_paused,continue_decision;
static int verdict,reader_result;
static void rcu_read_lock(void){assert(pthread_mutex_lock(&rcu_mu)==0);if(!read_depth++)++readers;assert(pthread_mutex_unlock(&rcu_mu)==0);}
static void rcu_read_unlock(void){assert(pthread_mutex_lock(&rcu_mu)==0);assert(read_depth);if(!--read_depth)--readers;pthread_cond_broadcast(&rcu_cv);assert(pthread_mutex_unlock(&rcu_mu)==0);}
static int gta3xlwifi_egress_policy(struct sock*sk,struct sk_buff*skb){(void)sk;(void)skb;assert(read_depth);rcu_read_lock();int result=verdict;rcu_read_unlock();assert(pthread_mutex_lock(&decision_mu)==0);if(pause_decision){decision_paused=true;pthread_cond_broadcast(&decision_cv);while(!continue_decision)pthread_cond_wait(&decision_cv,&decision_mu);}assert(pthread_mutex_unlock(&decision_mu)==0);return result;}
int gta3xlwifi_accounted_egress(struct sock *sk,struct sk_buff *skb)
{
    int result;
    rcu_read_lock();
    result=gta3xlwifi_egress_policy(sk,skb);
    if(result&&skb)
        gta3xlwifi_iface_account(skb,skb->dev?skb->dev->ifindex:0,true,true);
    rcu_read_unlock();
    return result;
}
static void*run_reader(void*p){reader_result=gta3xlwifi_accounted_egress(NULL,p);return NULL;}
static void*run_hold(void*p){(void)p;assert(pthread_mutex_lock(&rcu_mu)==0);hold_entered=true;pthread_cond_broadcast(&rcu_cv);while(readers)pthread_cond_wait(&rcu_cv,&rcu_mu);held=true;assert(pthread_mutex_unlock(&rcu_mu)==0);return NULL;}
int main(void){
 unsigned before=cases;struct net_device dev={17};struct sk_buff frame={.dev=&dev};
 const unsigned lengths[]={0,1,1500,1501,4096,65535};const int results[]={0,-EPERM,-EOPNOTSUPP,-ENOMEM,1};
 for(unsigned family=0;family<2;family++)for(unsigned i=0;i<6;i++)for(unsigned j=0;j<5;j++){
  reset_store();memset(&oracle_value,0,sizeof(oracle_value));frame.len=lengths[i];frame.protocol=htons(family?ETH_P_IPV6:ETH_P_IP);frame.dev=&dev;verdict=results[j];
  struct __sk_buff oracle={frame.len,frame.protocol,0,NULL};u32 key=0;
  T(gta3xlwifi_iface_account(&frame,17,true,false)==0);update_iface_stats_map(&oracle,&key,(struct egress_bool){true},(struct kver_uint){(4<<16)|(9<<8)},(struct undo_bool){false});
  T(gta3xlwifi_accounted_egress(NULL,&frame)==verdict);if(verdict)update_iface_stats_map(&oracle,&key,(struct egress_bool){true},(struct kver_uint){(4<<16)|(9<<8)},(struct undo_bool){true});
  T(iface_count==1&&iface_rows[0].tx_packets==oracle_value.txPackets&&iface_rows[0].tx_bytes==oracle_value.txBytes&&!iface_rows[0].rx_packets&&!iface_rows[0].rx_bytes&&!readers&&!read_depth);T(iface_sequence==(unsigned)(verdict?2:1));
 }
 reset_store();verdict=-EPERM;frame.dev=NULL;frame.len=64;T(gta3xlwifi_iface_account(&frame,0,true,false)==0);T(gta3xlwifi_accounted_egress(NULL,&frame)==-EPERM&&iface_count==1&&iface_rows[0].ifindex==0&&!iface_rows[0].tx_packets&&!iface_rows[0].tx_bytes);T(gta3xlwifi_accounted_egress(NULL,NULL)==-EPERM&&iface_sequence==2);
 reset_store();frame.dev=&dev;T(gta3xlwifi_accounted_egress(NULL,&frame)==-EPERM&&iface_rows[0].tx_packets==UINT64_MAX&&iface_rows[0].tx_bytes==(u64)-64); /* Exact A17 unsigned UNDO without a prior producer. */
 reset_store();for(u32 n=0;n<1000;n++)assert(!gta3xlwifi_iface_account(&frame,n,true,false));dev.ifindex=1001;T(gta3xlwifi_iface_account(&frame,1001,true,false)==-ENOSPC);T(gta3xlwifi_accounted_egress(NULL,&frame)==-EPERM&&iface_lost_updates==2&&iface_count==1000);
 reset_store();dev.ifindex=17;frame.len=4096;assert(!gta3xlwifi_iface_account(&frame,17,true,false));pause_decision=true;verdict=-EPERM;pthread_t reader,holder;T(pthread_create(&reader,NULL,run_reader,&frame)==0);
 assert(pthread_mutex_lock(&decision_mu)==0);while(!decision_paused)pthread_cond_wait(&decision_cv,&decision_mu);assert(pthread_mutex_unlock(&decision_mu)==0);
 T(pthread_create(&holder,NULL,run_hold,NULL)==0);assert(pthread_mutex_lock(&rcu_mu)==0);while(!hold_entered)pthread_cond_wait(&rcu_cv,&rcu_mu);T(readers==1&&!held&&iface_rows[0].tx_packets>0);assert(pthread_mutex_unlock(&rcu_mu)==0);
 assert(pthread_mutex_lock(&decision_mu)==0);continue_decision=true;pthread_cond_broadcast(&decision_cv);assert(pthread_mutex_unlock(&decision_mu)==0);
 T(pthread_join(reader,NULL)==0&&pthread_join(holder,NULL)==0);T(reader_result==-EPERM&&held&&!readers&&!iface_rows[0].tx_packets&&!iface_rows[0].tx_bytes&&iface_sequence==2);
 printf("passed_cases=%u\n",cases-before);return 0;
}
