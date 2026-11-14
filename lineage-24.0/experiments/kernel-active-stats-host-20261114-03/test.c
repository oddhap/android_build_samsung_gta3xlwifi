
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
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
#include <linux/netfilter/gta3xlwifi_packet_stats.h>
#include <linux/netfilter/gta3xlwifi_uid_permissions.h>
#include <linux/netfilter/gta3xlwifi_local_network.h>
#include <linux/netfilter/gta3xlwifi_loopback.h>
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
typedef uint32_t u32;typedef uint64_t u64;
#define __user
#define EXPORT_SYMBOL_GPL(x)
#define CONFIG_INET 1
#define CONFIG_IPV6 1
#define READ_ONCE(x) (x)
#define DEFINE_SPINLOCK(x) pthread_mutex_t x=PTHREAD_MUTEX_INITIALIZER
#define spin_lock_bh(x) assert(pthread_mutex_lock(x)==0)
#define spin_unlock_bh(x) assert(pthread_mutex_unlock(x)==0)
struct sock{bool full;u32 sk_protocol;};
struct shared_info{unsigned short gso_segs;};
struct sk_buff{u32 len;uint16_t protocol;struct shared_info shared;};
static struct shared_info *skb_shinfo(const struct sk_buff*s){return (void*)&s->shared;}
static bool sk_fullsock(const struct sock*s){return s->full;}
static u32 hash_32(u32 key,unsigned bits){return (key*0x9e370001U)>>(32-bits);}
static unsigned from_calls,to_calls,from_fault,to_fault,allocs,frees;static bool alloc_fault;
static void(*copy_hook)(void*,const void*,size_t);
static int copy_from_user(void*d,const void*s,size_t n){if(++from_calls==from_fault||!s)return 1;memcpy(d,s,n);return 0;}
static int copy_to_user(void*d,const void*s,size_t n){if(++to_calls==to_fault||!d)return 1;if(copy_hook)copy_hook(d,s,n);memcpy(d,s,n);return 0;}
static void*vzalloc(size_t n){if(alloc_fault)return NULL;void*p=calloc(1,n);if(p)++allocs;return p;}
static void vfree(void*p){if(p){++frees;free(p);}}
static void sort(void*p,size_t n,size_t size,int(*cmp)(const void*,const void*),void*swap){assert(!swap);qsort(p,n,size,cmp);}
#define STATS_HASH_BITS 13
#define APP_HASH_BITS 14
#define SET_HASH_BITS 15
struct stats_row { u32 next; struct gta3xlwifi_packet_stats_entry entry; };
struct app_row { u32 next; struct gta3xlwifi_app_stats_entry entry; };
struct set_row { u32 next, uid, value; };
struct stats_bank {
    u32 heads[1U << STATS_HASH_BITS], count;
    struct stats_row rows[GTA3XLWIFI_PACKET_STATS_MAX];
    u64 lost, sequence, last_ack;
    bool pending;
};
static DEFINE_SPINLOCK(stats_lock);
static struct stats_bank stats_banks[2];
/* Keep large stores in BSS rather than embedding zero arrays in Image data. */
static u64 stats_bank_epoch[2] = { 1, 0 };
static u32 stats_active;
static u64 stats_epoch = 1, stats_total_lost;
static u32 app_heads[1U << APP_HASH_BITS], app_count;
static struct app_row app_rows[GTA3XLWIFI_APP_STATS_MAX];
static u64 app_lost, app_sequence;
static u32 set_heads[1U << SET_HASH_BITS], set_count, set_cursor, set_free;
static struct set_row set_rows[GTA3XLWIFI_COUNTERSET_MAX];
static void stats_loss(u64 *value) { if (*value != ~(u64)0) ++*value; }
static u32 stats_rotate(u32 v, unsigned n) { return (v << n) | (v >> (32 - n)); }
static u32 stats_hash(const struct gta3xlwifi_stats_key *key)
{
    return hash_32(key->uid ^ stats_rotate(key->tag,7) ^
                   stats_rotate(key->counterset,15) ^ stats_rotate(key->ifindex,23),
                   STATS_HASH_BITS);
}
static void packet_amount(struct sock *sk,const struct sk_buff *skb,u64 *packets,u64 *bytes)
{
    /* Exact pinned A17 >=5.4 UID/app branch, using REAL4.4 GSO metadata.
     * tcp_offload.c in this tree sets gso_segs for segmentation and GRO.
     * Unlike interface-XT's explicit4.9 estimator, do not infer from length.
     */
    u64 p=1,b=skb->len;
    u32 segs=skb_shinfo(skb)->gso_segs;
    if(segs>1){
        bool tcp_or_unknown=!sk||!sk_fullsock(sk)||sk->sk_protocol==IPPROTO_TCP;
        int overhead=(skb->protocol==htons(ETH_P_IPV6)?sizeof(struct ipv6hdr):sizeof(struct iphdr))+
                     (tcp_or_unknown?sizeof(struct tcphdr)+12:sizeof(struct udphdr));
        u64 payload=b-overhead;
        p=segs;b=overhead*p+payload;
    }
    *packets=p;*bytes=b;
}
u32 gta3xlwifi_packet_hooks_features(void)
{
#if defined(CONFIG_INET) && defined(CONFIG_IPV6)
    /* This staged source includes both real packet producer bodies and the
     * original full-socket receive/output call sites. Their actual compiled
     * reachability is a mandatory build check, not a BPF/runtime Ready claim.
     */
    return GTA3XLWIFI_UID_CAP_PACKET_STATS_HOOKS;
#else
    return 0;
#endif
}
EXPORT_SYMBOL_GPL(gta3xlwifi_packet_hooks_features);
u32 gta3xlwifi_packet_stats_features(void)
{
#if defined(CONFIG_INET) && defined(CONFIG_IPV6)
    return GTA3XLWIFI_UID_CAP_PACKET_STATS_STORE | GTA3XLWIFI_UID_CAP_ACTIVE_PACKET_STATS;
#else
    return 0;
#endif
}
EXPORT_SYMBOL_GPL(gta3xlwifi_packet_stats_features);
static u32 counterset(u32 uid)
{
    u32 n;for(n=set_heads[hash_32(uid,SET_HASH_BITS)];n;n=set_rows[n-1].next)
        if(set_rows[n-1].uid==uid)return set_rows[n-1].value;
    return 0;
}
static struct gta3xlwifi_packet_stats_entry *stats_entry(struct stats_bank *bank,
                                                        const struct gta3xlwifi_stats_key *key)
{
    u32 bucket=stats_hash(key),n;struct stats_row *row;
    for(n=bank->heads[bucket];n;n=bank->rows[n-1].next)
        if(!memcmp(&bank->rows[n-1].entry.key,key,sizeof(*key)))return &bank->rows[n-1].entry;
    if(bank->count==GTA3XLWIFI_PACKET_STATS_MAX)return NULL;
    row=&bank->rows[bank->count++];memset(row,0,sizeof(*row));row->entry.key=*key;
    row->next=bank->heads[bucket];bank->heads[bucket]=bank->count;return &row->entry;
}
static struct gta3xlwifi_app_stats_entry *app_entry(u32 uid)
{
    u32 bucket=hash_32(uid,APP_HASH_BITS),n;struct app_row *row;
    for(n=app_heads[bucket];n;n=app_rows[n-1].next)
        if(app_rows[n-1].entry.uid==uid)return &app_rows[n-1].entry;
    if(app_count==GTA3XLWIFI_APP_STATS_MAX)return NULL;
    row=&app_rows[app_count++];memset(row,0,sizeof(*row));row->entry.uid=uid;
    row->next=app_heads[bucket];app_heads[bucket]=app_count;return &row->entry;
}
int gta3xlwifi_packet_stats_record(struct sock *sk,const struct sk_buff *skb,
                                 u32 uid,u32 tag,u32 ifindex,bool output)
{
    struct gta3xlwifi_stats_key key={uid,tag,0,ifindex};
    struct gta3xlwifi_packet_stats_entry *entry;
    struct gta3xlwifi_app_stats_entry *app;
    struct stats_bank *bank;u64 packets,bytes;int result=0;
    if(!skb)return -EINVAL;
    packet_amount(sk,skb,&packets,&bytes);
    spin_lock_bh(&stats_lock);bank=&stats_banks[stats_active];key.counterset=counterset(uid);
    entry=stats_entry(bank,&key);app=app_entry(uid);
    /* These are independent A17 stores: a full bank does not prevent the app
     * update, and a full app store does not prevent the bank update.
     */
    if(entry){if(output){entry->tx_packets+=packets;entry->tx_bytes+=bytes;}
              else{entry->rx_packets+=packets;entry->rx_bytes+=bytes;}}
    else{stats_loss(&bank->lost);stats_loss(&stats_total_lost);result=-ENOSPC;}
    if(app){if(output){app->tx_packets+=packets;app->tx_bytes+=bytes;}
            else{app->rx_packets+=packets;app->rx_bytes+=bytes;}}
    else{stats_loss(&app_lost);result=-ENOSPC;}
    ++bank->sequence;++app_sequence;spin_unlock_bh(&stats_lock);return result;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_packet_stats_record);
void gta3xlwifi_packet_stats_lost(void)
{
    /* Caller could not establish real accounting identity. Never invent UID0.
     * Counts failed accounting attempts, not a fabricated packet/byte estimate.
     */
    spin_lock_bh(&stats_lock);stats_loss(&stats_banks[stats_active].lost);
    stats_loss(&stats_total_lost);stats_loss(&app_lost);
    ++stats_banks[stats_active].sequence;++app_sequence;spin_unlock_bh(&stats_lock);
}
EXPORT_SYMBOL_GPL(gta3xlwifi_packet_stats_lost);
static long stats_state(unsigned long arg)
{
    struct gta3xlwifi_packet_stats_state value;memset(&value,0,sizeof(value));
    spin_lock_bh(&stats_lock);value.version=GTA3XLWIFI_PACKET_STATS_VERSION;
    value.active_bank=stats_active;value.active_epoch=stats_epoch;
    value.bank_count[0]=stats_banks[0].count;value.bank_count[1]=stats_banks[1].count;
    value.bank_epoch[0]=stats_bank_epoch[0];value.bank_epoch[1]=stats_bank_epoch[1];
    value.bank_lost[0]=stats_banks[0].lost;value.bank_lost[1]=stats_banks[1].lost;
    value.app_count=app_count;value.counterset_count=set_count;value.app_lost=app_lost;
    value.total_stats_lost=stats_total_lost;
    value.pending_mask=(stats_banks[0].pending?1U:0)|(stats_banks[1].pending?2U:0);
    spin_unlock_bh(&stats_lock);
    return copy_to_user((void __user *)arg,&value,sizeof(value))?-EFAULT:0;
}
static int stats_compare(const void *a,const void *b)
{
    const struct gta3xlwifi_stats_key *x=&((const struct gta3xlwifi_packet_stats_entry *)a)->key;
    const struct gta3xlwifi_stats_key *y=&((const struct gta3xlwifi_packet_stats_entry *)b)->key;
#define CMP_FIELD(f) if(x->f!=y->f)return x->f<y->f?-1:1
    CMP_FIELD(uid);CMP_FIELD(tag);CMP_FIELD(counterset);CMP_FIELD(ifindex);
#undef CMP_FIELD
    return 0;
}
static int app_compare(const void *a,const void *b)
{
    u32 x=((const struct gta3xlwifi_app_stats_entry *)a)->uid;
    u32 y=((const struct gta3xlwifi_app_stats_entry *)b)->uid;
    return x<y?-1:x>y?1:0;
}
static long stats_read(unsigned long arg)
{
    struct gta3xlwifi_packet_stats_transfer request,answer;
    void *rows=NULL;u32 limit,actual,i,bank;size_t size;bool app,live;int result=0;
    if(copy_from_user(&request,(void __user *)arg,sizeof(request)))return -EFAULT;
    if(request.version!=GTA3XLWIFI_PACKET_STATS_VERSION||request.kind>GTA3XLWIFI_STATS_ACTIVE||
       request.reserved||request.lost_updates||request.sequence|| (!!request.count!=!!request.entries))return -EINVAL;
    app=request.kind==GTA3XLWIFI_STATS_APP_UID;
    live=request.kind==GTA3XLWIFI_STATS_ACTIVE;
    if(live&&!request.epoch)return -EINVAL;
    if(app&&request.epoch)return -EINVAL;
    limit=app?GTA3XLWIFI_APP_STATS_MAX:GTA3XLWIFI_PACKET_STATS_MAX;
    size=app?sizeof(struct gta3xlwifi_app_stats_entry):sizeof(struct gta3xlwifi_packet_stats_entry);
    if(request.count>limit)return -EINVAL;
    if(request.count){rows=vzalloc(request.count*size);if(!rows)return -ENOMEM;}
    answer=request;spin_lock_bh(&stats_lock);
    bank=live?stats_active:request.kind;
    if(!app&&!live&&bank==stats_active)result=-EBUSY;
    else if(!app&&!live&&!stats_banks[bank].pending)result=-ENODATA;
    else if(!app&&request.epoch!=stats_bank_epoch[bank])result=-ESTALE;
    if(!result){
        actual=app?app_count:stats_banks[bank].count;
        answer.count=actual;answer.epoch=app?0:stats_bank_epoch[bank];
        answer.lost_updates=app?app_lost:stats_banks[bank].lost;
        answer.sequence=app?app_sequence:stats_banks[bank].sequence;
        if(request.count&&request.count<actual)result=-ENOSPC;
        else if(request.count){
            if(app)for(i=0;i<actual;++i)((struct gta3xlwifi_app_stats_entry *)rows)[i]=app_rows[i].entry;
            else for(i=0;i<actual;++i)((struct gta3xlwifi_packet_stats_entry *)rows)[i]=stats_banks[bank].rows[i].entry;
        }
    }
    spin_unlock_bh(&stats_lock);
    if(!result&&request.count){
        sort(rows,answer.count,size,app?app_compare:stats_compare,NULL);
        if(copy_to_user((void __user *)(unsigned long)request.entries,rows,answer.count*size))result=-EFAULT;
    }
    if(!result&&copy_to_user((void __user *)arg,&answer,sizeof(answer)))result=-EFAULT;
    vfree(rows);return result;
}
static long stats_swap(unsigned long arg)
{
    struct gta3xlwifi_packet_stats_swap request,answer;u32 next;int result=0;
    if(copy_from_user(&request,(void __user *)arg,sizeof(request)))return -EFAULT;
    if(request.version!=GTA3XLWIFI_PACKET_STATS_VERSION||request.active_bank>1||
       !request.active_epoch||request.inactive_bank||request.reserved||request.inactive_epoch)return -EINVAL;
    spin_lock_bh(&stats_lock);next=1U-stats_active;answer=request;
    if(request.active_bank!=stats_active||request.active_epoch!=stats_epoch)result=-ESTALE;
    else if(stats_banks[next].pending)result=-EBUSY;
    else if(stats_epoch==~(u64)0)result=-EOVERFLOW;
    else{
        stats_banks[stats_active].pending=true;
        answer.inactive_bank=stats_active;answer.inactive_epoch=stats_epoch;
        stats_active=next;++stats_epoch;stats_bank_epoch[next]=stats_epoch;
        stats_banks[next].sequence=0;
        answer.active_bank=stats_active;answer.active_epoch=stats_epoch;
    }
    spin_unlock_bh(&stats_lock);
    if(!result&&copy_to_user((void __user *)arg,&answer,sizeof(answer)))result=-EFAULT;
    /* No rollback after user-copy fault: real producers may have entered the
     * new bank. STATE exposes the committed result for explicit recovery.
     */
    return result;
}
static long stats_ack(unsigned long arg)
{
    struct gta3xlwifi_packet_stats_ack request;struct stats_bank *bank;int result=0;
    if(copy_from_user(&request,(void __user *)arg,sizeof(request)))return -EFAULT;
    if(request.version!=GTA3XLWIFI_PACKET_STATS_VERSION||request.bank>1||!request.epoch||request.reserved)return -EINVAL;
    spin_lock_bh(&stats_lock);bank=&stats_banks[request.bank];
    if(bank->last_ack==request.epoch){ /* Safe idempotent receipt, even after reuse. */ }
    else if(request.bank==stats_active||!bank->pending||stats_bank_epoch[request.bank]!=request.epoch)result=-ESTALE;
    else{
        /* Reused rows are zeroed on allocation. Avoid clearing240KB under BH
         * lock; resetting heads/count is sufficient and never leaks stale rows.
         */
        memset(bank->heads,0,sizeof(bank->heads));bank->count=0;bank->lost=0;
        bank->pending=false;bank->last_ack=request.epoch;
    }
    spin_unlock_bh(&stats_lock);return result;
}
static int set_counterset(u32 uid,u32 value)
{
    u32 bucket=hash_32(uid,SET_HASH_BITS),*link=&set_heads[bucket],n;
    struct set_row *row;
    while(*link){n=*link;row=&set_rows[n-1];if(row->uid==uid){
        if(value)row->value=value;
        else{*link=row->next;memset(row,0,sizeof(*row));row->next=set_free;set_free=n;--set_count;}
        return 0;
    }link=&row->next;}
    if(!value)return 0;
    if(set_count==GTA3XLWIFI_COUNTERSET_MAX)return -ENOSPC;
    if(set_free){n=set_free;set_free=set_rows[n-1].next;}else n=++set_cursor;
    row=&set_rows[n-1];memset(row,0,sizeof(*row));row->uid=uid;row->value=value;
    row->next=set_heads[bucket];set_heads[bucket]=n;++set_count;return 0;
}
static void stats_remove_uid(u32 uid)
{
    u32 b,i,n;struct stats_bank *bank;
    for(b=0;b<2;++b){
        bank=&stats_banks[b];n=0;
        for(i=0;i<bank->count;++i)if(bank->rows[i].entry.key.uid!=uid)
            bank->rows[n++].entry=bank->rows[i].entry;
        bank->count=n;memset(bank->heads,0,sizeof(bank->heads));
        for(i=0;i<n;++i){u32 h=stats_hash(&bank->rows[i].entry.key);bank->rows[i].next=bank->heads[h];bank->heads[h]=i+1;}
        ++bank->sequence;
    }
    n=0;for(i=0;i<app_count;++i)if(app_rows[i].entry.uid!=uid)app_rows[n++].entry=app_rows[i].entry;
    app_count=n;memset(app_heads,0,sizeof(app_heads));
    for(i=0;i<n;++i){u32 h=hash_32(app_rows[i].entry.uid,APP_HASH_BITS);app_rows[i].next=app_heads[h];app_heads[h]=i+1;}
    ++app_sequence;set_counterset(uid,0);
}
static long stats_edit(unsigned long arg)
{
    struct gta3xlwifi_packet_stats_edit request;int result=0;
    if(copy_from_user(&request,(void __user *)arg,sizeof(request)))return -EFAULT;
    if(request.version!=GTA3XLWIFI_PACKET_STATS_VERSION||request.reserved||request.tag)return -EINVAL;
    if(request.operation==GTA3XLWIFI_STATS_SET_COUNTERSET){if(request.counterset>1)return -EINVAL;}
    else if(request.operation==GTA3XLWIFI_STATS_DELETE_UID){if(request.counterset)return -EINVAL;}
    else return -EINVAL;
    spin_lock_bh(&stats_lock);
    if(request.operation==GTA3XLWIFI_STATS_SET_COUNTERSET)result=set_counterset(request.uid,request.counterset);
    else if(stats_banks[0].pending||stats_banks[1].pending)result=-EBUSY;
    else stats_remove_uid(request.uid);
    spin_unlock_bh(&stats_lock);return result;
}
long gta3xlwifi_packet_stats_ioctl(unsigned int cmd,unsigned long arg)
{
    if(cmd!=GTA3XLWIFI_STATS_GET_STATE&&cmd!=GTA3XLWIFI_STATS_READ&&cmd!=GTA3XLWIFI_STATS_SWAP&&
       cmd!=GTA3XLWIFI_STATS_ACK&&cmd!=GTA3XLWIFI_STATS_EDIT)return -ENOTTY;
    if(!arg)return -EFAULT;
    if(!gta3xlwifi_packet_stats_features())return -EOPNOTSUPP;
    switch(cmd){
    case GTA3XLWIFI_STATS_GET_STATE:return stats_state(arg);
    case GTA3XLWIFI_STATS_READ:return stats_read(arg);
    case GTA3XLWIFI_STATS_SWAP:return stats_swap(arg);
    case GTA3XLWIFI_STATS_ACK:return stats_ack(arg);
    default:return stats_edit(arg);
    }
}
EXPORT_SYMBOL_GPL(gta3xlwifi_packet_stats_ioctl);

struct file{int id;};struct pid{int id;};
static struct file owner={1},other_file={2};static struct pid owner_pid={1},other_pid={2};
static struct file*netpolicy_owner_file=&owner;static struct pid*netpolicy_owner_pid=&owner_pid,*fixture_pid=&owner_pid;
static bool privileged=true,netpolicy_held=true;
static void*current;
static struct pid*task_tgid(void*p){assert(p==current);return fixture_pid;}
static bool netpolicy_privileged(void){return privileged;}
static pthread_mutex_t netpolicy_lock=PTHREAD_MUTEX_INITIALIZER;
#define mutex_lock(x) assert(pthread_mutex_lock(x)==0)
#define mutex_unlock(x) assert(pthread_mutex_unlock(x)==0)
static u32 gta3xlwifi_uid_permissions_features(void){return 0;}
static u32 gta3xlwifi_lna_packet_features(void){return 0;}
static u32 gta3xlwifi_receive_features(void){return 0;}
static u32 gta3xlwifi_egress_features(void){return 0;}
static u32 gta3xlwifi_loopback_features(void){return 0;}
static u32 gta3xlwifi_socket_tables_features(void){return 0;}
static u32 gta3xlwifi_iface_stats_features(void){return 0;}
static long gta3xlwifi_iface_stats_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"unrelated interface fixture");return -ENOTTY;}
static long gta3xlwifi_loopback_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"unrelated loopback fixture");return -ENOTTY;}
static long gta3xlwifi_lna_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"unrelated LNA fixture");return -ENOTTY;}
static long gta3xlwifi_uid_permissions_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"unrelated permissions fixture");return -ENOTTY;}
#include <linux/netfilter/gta3xlwifi_runtime_policy.h>
static u32 gta3xlwifi_runtime_features(void){return 0;}
static long gta3xlwifi_runtime_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"scoped packet fixture entered runtime image");return -ENOTTY;}
static long netpolicy_image_ioctl(struct file *file, unsigned int cmd,
                                  unsigned long arg)
{
	long ret;
	if (cmd != GTA3XLWIFI_UID_FEATURES && cmd != GTA3XLWIFI_UID_SET_IMAGE &&
	    cmd != GTA3XLWIFI_UID_GET_IMAGE && cmd != GTA3XLWIFI_LNA_SET_IMAGE &&
	    cmd != GTA3XLWIFI_LNA_GET_IMAGE && cmd != GTA3XLWIFI_LOOPBACK_GET_EVENTS && cmd != GTA3XLWIFI_IFACE_STATS_GET && cmd != GTA3XLWIFI_STATS_GET_STATE && cmd != GTA3XLWIFI_STATS_READ && cmd != GTA3XLWIFI_STATS_SWAP && cmd != GTA3XLWIFI_STATS_ACK && cmd != GTA3XLWIFI_STATS_EDIT && cmd != GTA3XLWIFI_RUNTIME_GET && cmd != GTA3XLWIFI_RUNTIME_SET)
		return -ENOTTY;
	if (cmd == GTA3XLWIFI_UID_FEATURES && arg)
		return -EINVAL;
	if (cmd != GTA3XLWIFI_UID_FEATURES && !arg)
		return -EFAULT;
	if (!netpolicy_privileged())
		return -EPERM;
	mutex_lock(&netpolicy_lock);
	if (!netpolicy_owner_file)
		ret = -ENOTCONN;
	else if (netpolicy_owner_file != file ||
	         netpolicy_owner_pid != task_tgid(current))
		ret = -EPERM;
	else if (cmd == GTA3XLWIFI_UID_FEATURES)
		ret = gta3xlwifi_uid_permissions_features() | GTA3XLWIFI_UID_CAP_LNA_STORE |
		      gta3xlwifi_lna_packet_features() | gta3xlwifi_receive_features() | gta3xlwifi_egress_features() | gta3xlwifi_loopback_features() |
		      gta3xlwifi_socket_tables_features() | gta3xlwifi_iface_stats_features() | gta3xlwifi_packet_stats_features() | gta3xlwifi_packet_hooks_features() | gta3xlwifi_runtime_features();
	else if ((cmd == GTA3XLWIFI_UID_SET_IMAGE || cmd == GTA3XLWIFI_LNA_SET_IMAGE || cmd == GTA3XLWIFI_RUNTIME_SET) &&
	         !READ_ONCE(netpolicy_held))
		ret = -EBUSY;
	else if (cmd == GTA3XLWIFI_RUNTIME_GET || cmd == GTA3XLWIFI_RUNTIME_SET)
		ret = gta3xlwifi_runtime_ioctl(cmd, arg);
	else if (cmd == GTA3XLWIFI_STATS_GET_STATE || cmd == GTA3XLWIFI_STATS_READ || cmd == GTA3XLWIFI_STATS_SWAP || cmd == GTA3XLWIFI_STATS_ACK || cmd == GTA3XLWIFI_STATS_EDIT)
		ret = gta3xlwifi_packet_stats_ioctl(cmd, arg);
	else if (cmd == GTA3XLWIFI_IFACE_STATS_GET)
		ret = gta3xlwifi_iface_stats_ioctl(cmd, arg);
	else if (cmd == GTA3XLWIFI_LOOPBACK_GET_EVENTS)
		ret = gta3xlwifi_loopback_ioctl(cmd, arg);
	else if (cmd == GTA3XLWIFI_LNA_SET_IMAGE || cmd == GTA3XLWIFI_LNA_GET_IMAGE)
		ret = gta3xlwifi_lna_ioctl(cmd, arg);
	else
		ret = gta3xlwifi_uid_permissions_ioctl(cmd, arg);
	mutex_unlock(&netpolicy_lock);
	return ret;
}
#define function static
#define KVER_IS_AT_LEAST(k,a,b) ((k).version>=(((a)<<16)|((b)<<8)))
#define BPF_NOEXIST 1
struct kver_uint{unsigned version;};struct egress_bool{bool egress;};struct undo_bool{bool undo;};
struct bpf_sock{u32 protocol;bool full;};struct __sk_buff{u32 len;uint16_t protocol;u32 gso_segs;struct bpf_sock*sk;};
typedef struct{u64 rxPackets,rxBytes,txPackets,txBytes;}StatsValue;
static StatsValue oracle_value;
static StatsValue*bpf_app_uid_stats_map_lookup_elem(const u32*key){assert(!*key);return &oracle_value;}
static void bpf_app_uid_stats_map_update_elem(const u32*k,StatsValue*v,unsigned flags){(void)k;(void)v;assert(flags==BPF_NOEXIST);}
static struct bpf_sock*bpf_sk_fullsock(struct bpf_sock*s){return s->full?s:NULL;}
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


DEFINE_UPDATE_STATS(app_uid_stats_map,uint32_t)

static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
static void reset_store(void){
 assert(allocs==frees);memset(stats_banks,0,sizeof(stats_banks));stats_bank_epoch[0]=1;stats_bank_epoch[1]=0;stats_active=0;stats_epoch=1;stats_total_lost=0;memset(app_heads,0,sizeof(app_heads));memset(app_rows,0,sizeof(app_rows));app_count=0;app_lost=app_sequence=0;memset(set_heads,0,sizeof(set_heads));memset(set_rows,0,sizeof(set_rows));set_count=set_cursor=set_free=0;from_calls=to_calls=from_fault=to_fault=0;alloc_fault=false;copy_hook=NULL;netpolicy_owner_file=&owner;netpolicy_owner_pid=fixture_pid=&owner_pid;privileged=true;netpolicy_held=true;
}
static long io(unsigned cmd,void*p){return netpolicy_image_ioctl(&owner,cmd,(unsigned long)p);}
static struct gta3xlwifi_packet_stats_state state(void){struct gta3xlwifi_packet_stats_state s;memset(&s,0xff,sizeof(s));assert(io(GTA3XLWIFI_STATS_GET_STATE,&s)==0);return s;}
static struct gta3xlwifi_packet_stats_swap flip(void){struct gta3xlwifi_packet_stats_state s=state();struct gta3xlwifi_packet_stats_swap q={1,s.active_bank,s.active_epoch,0,0,0};assert(io(GTA3XLWIFI_STATS_SWAP,&q)==0);return q;}
static long ack(u32 bank,u64 epoch){struct gta3xlwifi_packet_stats_ack q={1,bank,epoch,0};return io(GTA3XLWIFI_STATS_ACK,&q);}
static long edit(u32 op,u32 uid,u32 value){struct gta3xlwifi_packet_stats_edit q={1,op,uid,0,value,0};return io(GTA3XLWIFI_STATS_EDIT,&q);}
static struct gta3xlwifi_packet_stats_transfer req(u32 kind,u64 epoch,void*rows,u32 count){return(struct gta3xlwifi_packet_stats_transfer){1,kind,epoch,count,0,(uintptr_t)rows,0,0};}
static struct sk_buff packet={64,0,{1}};
static struct gta3xlwifi_packet_stats_entry wire[5000];static struct gta3xlwifi_app_stats_entry apps[10000];
static void*producer(void*p){u32 uid=(uintptr_t)p;for(unsigned i=0;i<10000;i++)assert(!gta3xlwifi_packet_stats_record(NULL,&packet,uid,i&1,17,i&1));return NULL;}
static u64 collected[9];
static void drain(void){struct gta3xlwifi_packet_stats_swap f=flip();struct gta3xlwifi_packet_stats_transfer q=req(f.inactive_bank,f.inactive_epoch,wire,5000);assert(!io(GTA3XLWIFI_STATS_READ,&q));for(u32 i=0;i<q.count;i++){assert(wire[i].key.uid<9);collected[wire[i].key.uid]+=wire[i].rx_packets+wire[i].tx_packets;}assert(!q.lost_updates&&ack(f.inactive_bank,f.inactive_epoch)==0&&ack(f.inactive_bank,f.inactive_epoch)==0);}
static void record_during_copy(void*d,const void*s,size_t n){(void)s;(void)n;if(d==wire){copy_hook=NULL;assert(!gta3xlwifi_packet_stats_record(NULL,&packet,20002,7,17,true));}}
static int previous_regressions(void){
 T(sizeof(struct gta3xlwifi_stats_key)==16&&sizeof(struct gta3xlwifi_packet_stats_entry)==48&&sizeof(struct gta3xlwifi_app_stats_entry)==40);
 T(sizeof(struct gta3xlwifi_packet_stats_state)==88&&sizeof(struct gta3xlwifi_packet_stats_transfer)==48&&sizeof(struct gta3xlwifi_packet_stats_swap)==32&&sizeof(struct gta3xlwifi_packet_stats_ack)==24&&sizeof(struct gta3xlwifi_packet_stats_edit)==24);
 T(GTA3XLWIFI_STATS_GET_STATE==0x8058675b&&GTA3XLWIFI_STATS_READ==0xc030675c&&GTA3XLWIFI_STATS_SWAP==0xc020675d&&GTA3XLWIFI_STATS_ACK==0x4018675e&&GTA3XLWIFI_STATS_EDIT==0x4018675f);
 T(gta3xlwifi_packet_stats_features()==36864);reset_store();struct gta3xlwifi_packet_stats_state s=state();T(s.version==1&&!s.active_bank&&s.active_epoch==1&&s.bank_epoch[0]==1&&!s.pending_mask&&!s.reserved&&!s.app_count);
 const unsigned segments[]={0,1,2,64,65535};
 for(u32 len=0;len<65536;len++)for(unsigned family=0;family<3;family++)for(unsigned seg=0;seg<5;seg++)for(unsigned kind=0;kind<5;kind++)for(unsigned output=0;output<2;output++){
  struct sock sk={kind!=1,kind==2?IPPROTO_TCP:kind==3?IPPROTO_UDP:IPPROTO_GRE};struct sk_buff frame={len,htons(family==0?ETH_P_IP:family==1?ETH_P_IPV6:0),{segments[seg]}};struct bpf_sock osk={sk.sk_protocol,sk.full};struct __sk_buff oracle={len,frame.protocol,segments[seg],kind?&osk:NULL};u64 packets,bytes;packet_amount(kind?&sk:NULL,&frame,&packets,&bytes);memset(&oracle_value,0,sizeof(oracle_value));u32 key=0;update_app_uid_stats_map(&oracle,&key,(struct egress_bool){output},(struct kver_uint){(5<<16)|(4<<8)},(struct undo_bool){false});assert(packets==(output?oracle_value.txPackets:oracle_value.rxPackets)&&bytes==(output?oracle_value.txBytes:oracle_value.rxBytes));++comparisons;
 }
 T(gta3xlwifi_packet_stats_record(NULL,NULL,0,0,0,false)==-EINVAL);
 reset_store();T(edit(GTA3XLWIFI_STATS_SET_COUNTERSET,3,1)==0);T(!gta3xlwifi_packet_stats_record(NULL,&packet,3,2,17,true));T(!gta3xlwifi_packet_stats_record(NULL,&packet,1,0,2,false));T(!gta3xlwifi_packet_stats_record(NULL,&packet,3,1,4,true));struct gta3xlwifi_packet_stats_swap f=flip();struct gta3xlwifi_packet_stats_transfer q=req(f.inactive_bank,f.inactive_epoch,wire,5000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==3&&wire[0].key.uid==1&&wire[1].key.tag==1&&wire[2].key.counterset==1&&wire[2].tx_bytes==64);
 T(edit(GTA3XLWIFI_STATS_DELETE_UID,3,0)==-EBUSY);struct gta3xlwifi_packet_stats_swap stale={1,0,1,0,0,0};T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-ESTALE);stale=(struct gta3xlwifi_packet_stats_swap){1,1,2,0,0,0};T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-EBUSY);
 q=req(f.inactive_bank,f.inactive_epoch,NULL,0);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==3&&!q.entries);q=req(f.inactive_bank,f.inactive_epoch,wire,1);T(io(GTA3XLWIFI_STATS_READ,&q)==-ENOSPC&&q.count==1);q=req(f.inactive_bank,f.inactive_epoch+1,wire,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-ESTALE);q=req(1,2,wire,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-EBUSY);
 q=req(2,0,apps,10000);memset(apps,0xff,sizeof(apps));T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==2&&apps[0].uid==1&&apps[1].uid==3&&!apps[1].reserved&&apps[1].tx_packets==2);
 T(ack(f.inactive_bank,f.inactive_epoch)==0&&ack(f.inactive_bank,f.inactive_epoch)==0);q=req(f.inactive_bank,f.inactive_epoch,wire,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-ENODATA);T(edit(GTA3XLWIFI_STATS_DELETE_UID,3,0)==0&&app_count==1&&set_count==0);
 reset_store();gta3xlwifi_packet_stats_record(NULL,&packet,1,0,17,true);to_fault=to_calls+1;stale=(struct gta3xlwifi_packet_stats_swap){1,0,1,0,0,0};T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-EFAULT);to_fault=0;s=state();T(s.active_bank==1&&s.active_epoch==2&&s.pending_mask==1&&s.bank_count[0]==1);T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-ESTALE);T(!gta3xlwifi_packet_stats_record(NULL,&packet,2,0,17,true));T(ack(0,1)==0);f=flip();T(f.active_bank==0&&f.active_epoch==3&&f.inactive_bank==1&&f.inactive_epoch==2);gta3xlwifi_packet_stats_record(NULL,&packet,3,0,17,true);T(ack(0,1)==0&&stats_banks[0].count==1);T(ack(0,3)==-ESTALE);T(ack(1,2)==0);
 reset_store();gta3xlwifi_packet_stats_record(NULL,&packet,1,0,17,true);f=flip();for(unsigned fault=0;fault<8;fault++){q=req(f.inactive_bank,f.inactive_epoch,wire,5000);switch(fault){case 0:q.version=2;break;case 1:q.kind=4;break;case 2:q.reserved=1;break;case 3:q.lost_updates=1;break;case 4:q.sequence=1;break;case 5:q.count=5001;break;case 6:q.entries=0;break;case 7:q.count=0;break;}T(io(GTA3XLWIFI_STATS_READ,&q)==-EINVAL&&stats_banks[0].count==1&&stats_banks[0].pending);}
 q=req(2,1,apps,10000);T(io(GTA3XLWIFI_STATS_READ,&q)==-EINVAL);q=req(2,0,apps,10000);alloc_fault=true;T(io(GTA3XLWIFI_STATS_READ,&q)==-ENOMEM);alloc_fault=false;
 q=req(0,1,wire,5000);from_fault=from_calls+1;T(io(GTA3XLWIFI_STATS_READ,&q)==-EFAULT);from_fault=0;for(unsigned n=1;n<=2;n++){q=req(0,1,wire,5000);to_fault=to_calls+n;T(io(GTA3XLWIFI_STATS_READ,&q)==-EFAULT&&stats_banks[0].pending&&stats_banks[0].count==1);to_fault=0;}
 q=req(0,1,wire,5000);copy_hook=record_during_copy;T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==1&&wire[0].key.uid==1&&stats_banks[1].count==1&&app_count==2);T(ack(0,1)==0);
 reset_store();for(u32 tag=0;tag<5000;tag++)assert(!gta3xlwifi_packet_stats_record(NULL,&packet,7,tag,17,true));T(gta3xlwifi_packet_stats_record(NULL,&packet,7,5000,17,true)==-ENOSPC);T(stats_banks[0].lost==1&&stats_total_lost==1&&app_count==1&&app_rows[0].entry.tx_packets==5001&&!app_lost);T(!gta3xlwifi_packet_stats_record(NULL,&packet,7,0,17,true));stats_banks[0].lost=stats_total_lost=app_lost=UINT64_MAX;gta3xlwifi_packet_stats_lost();T(stats_banks[0].lost==UINT64_MAX&&stats_total_lost==UINT64_MAX&&app_lost==UINT64_MAX);
 reset_store();for(u32 uid=0;uid<10000;uid++){assert(!gta3xlwifi_packet_stats_record(NULL,&packet,uid,0,17,true));if((uid+1)%5000==0){f=flip();assert(!ack(f.inactive_bank,f.inactive_epoch));}}T(app_count==10000);T(gta3xlwifi_packet_stats_record(NULL,&packet,10000,0,17,true)==-ENOSPC&&app_lost==1&&!stats_banks[stats_active].lost&&stats_banks[stats_active].count==1);T(!gta3xlwifi_packet_stats_record(NULL,&packet,1,0,17,true));T(edit(GTA3XLWIFI_STATS_DELETE_UID,4000,0)==0&&app_count==9999&&app_lost==1);T(!gta3xlwifi_packet_stats_record(NULL,&packet,10000,0,17,true)&&app_count==10000);q=req(2,0,apps,10000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&apps[9999].uid==10000&&apps[9999].tx_packets==1&&!apps[9999].reserved&&q.lost_updates==1);
 reset_store();for(u32 uid=0;uid<20000;uid++)assert(!edit(GTA3XLWIFI_STATS_SET_COUNTERSET,uid,1));T(set_count==20000&&edit(GTA3XLWIFI_STATS_SET_COUNTERSET,20000,1)==-ENOSPC);T(edit(GTA3XLWIFI_STATS_SET_COUNTERSET,123,0)==0&&edit(GTA3XLWIFI_STATS_SET_COUNTERSET,20000,1)==0&&set_count==20000&&set_cursor==20000);T(!gta3xlwifi_packet_stats_record(NULL,&packet,123,0,17,true)&&!gta3xlwifi_packet_stats_record(NULL,&packet,20000,0,17,true)&&stats_banks[0].rows[0].entry.key.counterset==0&&stats_banks[0].rows[1].entry.key.counterset==1);T(edit(GTA3XLWIFI_STATS_SET_COUNTERSET,5,2)==-EINVAL);
 reset_store();gta3xlwifi_packet_stats_record(NULL,&packet,UINT32_MAX,UINT32_MAX,UINT32_MAX,true);stats_banks[0].rows[0].entry.tx_packets=app_rows[0].entry.tx_packets=UINT64_MAX;stats_banks[0].rows[0].entry.tx_bytes=app_rows[0].entry.tx_bytes=UINT64_MAX;stats_banks[0].sequence=app_sequence=UINT64_MAX;T(!gta3xlwifi_packet_stats_record(NULL,&packet,UINT32_MAX,UINT32_MAX,UINT32_MAX,true)&&!stats_banks[0].rows[0].entry.tx_packets&&stats_banks[0].rows[0].entry.tx_bytes==63&&!app_rows[0].entry.tx_packets&&!app_sequence&&!stats_banks[0].sequence);
 reset_store();stats_epoch=stats_bank_epoch[0]=UINT64_MAX;stale=(struct gta3xlwifi_packet_stats_swap){1,0,UINT64_MAX,0,0,0};T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-EOVERFLOW&&stats_active==0&&!stats_banks[0].pending);
 reset_store();const unsigned cmds[]={GTA3XLWIFI_STATS_GET_STATE,GTA3XLWIFI_STATS_READ,GTA3XLWIFI_STATS_SWAP,GTA3XLWIFI_STATS_ACK,GTA3XLWIFI_STATS_EDIT};unsigned char storage[128]={0};
 for(unsigned n=0;n<5;n++){privileged=false;T(io(cmds[n],storage)==-EPERM);privileged=true;fixture_pid=&other_pid;T(io(cmds[n],storage)==-EPERM);fixture_pid=&owner_pid;T(netpolicy_image_ioctl(&other_file,cmds[n],(unsigned long)storage)==-EPERM);netpolicy_owner_file=NULL;T(io(cmds[n],storage)==-ENOTCONN);netpolicy_owner_file=&owner;T(io(cmds[n],NULL)==-EFAULT);}
 T((netpolicy_image_ioctl(&owner,GTA3XLWIFI_UID_FEATURES,0)&4096)==4096);netpolicy_held=false;T(edit(GTA3XLWIFI_STATS_SET_COUNTERSET,1,1)==0);f=flip();T(ack(f.inactive_bank,f.inactive_epoch)==0);T(gta3xlwifi_packet_stats_ioctl(0,(unsigned long)&s)==-ENOTTY);
 reset_store();memset(collected,0,sizeof(collected));pthread_t threads[8];for(uintptr_t n=1;n<=8;n++)assert(!pthread_create(&threads[n-1],NULL,producer,(void*)n));for(unsigned n=0;n<100;n++)drain();for(unsigned n=0;n<8;n++)assert(!pthread_join(threads[n],NULL));drain();for(unsigned n=1;n<=8;n++)T(collected[n]==10000);q=req(2,0,apps,10000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==8&&!q.lost_updates);for(unsigned n=0;n<8;n++)T(apps[n].rx_packets+apps[n].tx_packets==10000);T(!stats_total_lost&&allocs==frees);
 printf("passed_cases=%u comparisons=%u concurrent_updates=80000\n",cases,comparisons);return 0;
}

static void check_active(u64 epoch){
 struct gta3xlwifi_packet_stats_entry rows[5000];struct gta3xlwifi_packet_stats_state before=state();
 struct gta3xlwifi_packet_stats_transfer q=req(GTA3XLWIFI_STATS_ACTIVE,epoch,rows,5000);
 T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.kind==3&&q.epoch==epoch&&q.count==before.bank_count[before.active_bank]&&q.lost_updates==before.bank_lost[before.active_bank]);
 struct gta3xlwifi_packet_stats_state after=state();T(!memcmp(&before,&after,sizeof(before)));
 for(u32 i=1;i<q.count;i++)T(stats_compare(&rows[i-1],&rows[i])<0);
}
int main(void){
 T(previous_regressions()==0);unsigned begin=cases;reset_store();check_active(1);
 struct sk_buff packet={64,0,{1}};struct gta3xlwifi_packet_stats_entry rows[5000];
 for(u32 i=0;i<30;i++)gta3xlwifi_packet_stats_record(NULL,&packet,i%3,i%5,17+i%2,true);
 check_active(1);struct gta3xlwifi_packet_stats_transfer q=req(3,1,NULL,0);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==30&&q.sequence==30);
 q=req(3,0,rows,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-EINVAL);q=req(3,2,rows,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-ESTALE);
 q=req(3,1,rows,1);T(io(GTA3XLWIFI_STATS_READ,&q)==-ENOSPC);check_active(1);
 struct gta3xlwifi_packet_stats_swap flip_result=flip();T(flip_result.active_epoch==2);check_active(2);q=req(3,1,rows,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-ESTALE);
 for(unsigned fault=0;fault<3;fault++){struct gta3xlwifi_packet_stats_state before=state();q=req(3,2,rows,5000);if(fault==0)alloc_fault=true;else to_fault=to_calls+fault;T(io(GTA3XLWIFI_STATS_READ,&q)==(fault==0?-ENOMEM:-EFAULT));alloc_fault=false;to_fault=0;struct gta3xlwifi_packet_stats_state after=state();T(!memcmp(&before,&after,sizeof(before)));}
 reset_store();for(u32 i=0;i<5001;i++)gta3xlwifi_packet_stats_record(NULL,&packet,i,0,17,true);check_active(1);q=req(3,1,rows,5000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==5000&&q.lost_updates==1);
 reset_store();pthread_t threads[8];for(uintptr_t i=1;i<=8;i++)assert(!pthread_create(&threads[i-1],NULL,producer,(void*)i));
 for(unsigned sample=0;sample<100;sample++){
  q=req(3,1,rows,5000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count<=16&&!q.lost_updates);u64 packets=0;for(u32 i=0;i<q.count;i++)packets+=rows[i].rx_packets+rows[i].tx_packets;T(packets==q.sequence);
 }
 for(unsigned i=0;i<8;i++){assert(!pthread_join(threads[i],NULL));}q=req(3,1,rows,5000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==16&&q.sequence==80000&&!q.lost_updates&&allocs==frees);
 T(!state().pending_mask&&state().active_epoch==1);printf("active_cases=%u total_cases=%u concurrent_active_updates=80000\n",cases-begin,cases);return 0;
}
