
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <linux/netfilter/gta3xlwifi_uid_permissions.h>
#include <linux/netfilter/gta3xlwifi_netpolicy.h>
typedef uint64_t u64;typedef uint32_t u32;
#define __rcu
#define __user
#define EXPORT_SYMBOL_GPL(x)
#define CONFIG_INET 1
#define CONFIG_IPV6 1
#define IS_ENABLED(x) (x)
#define BUILD_BUG_ON(x) _Static_assert(!(x),#x)
#define GLOBAL_ROOT_UID 0
#define CAP_NET_ADMIN 12
#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(n) assert(pthread_mutex_lock(n)==0)
#define mutex_unlock(n) assert(pthread_mutex_unlock(n)==0)
#define WRITE_ONCE(p,v) __atomic_store_n(&(p),(v),__ATOMIC_RELAXED)
#define READ_ONCE(p) __atomic_load_n(&(p),__ATOMIC_RELAXED)
#define smp_store_release(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
struct file{int id;};struct inode{int id;};typedef void* fl_owner_t;
struct pid{int refs;};struct task{u32 uid,euid;bool admin;struct pid*tgid;};
static struct pid parent_pid,child_pid;static struct task task={0,0,true,&parent_pid};
#define current (&task)
static int init_user_ns;
static u32 current_euid(void){return task.euid;}
static u32 current_uid(void){return task.uid;}
static bool uid_eq(u32 a,u32 b){return a==b;}
static u32 from_kuid(const void*n,u32 uid){assert(n==&init_user_ns);return uid;}
static bool ns_capable(const void*n,int c){assert(n==&init_user_ns&&c==CAP_NET_ADMIN);return task.admin;}
static struct pid*task_tgid(struct task*t){return t->tgid;}
static struct pid*get_pid(struct pid*p){++p->refs;return p;}
static void put_pid(struct pid*p){assert(p->refs>0);--p->refs;}
static unsigned network_graces,rcu_graces,rcu_depth,allocs,frees;
static int alloc_fail,from_calls,to_calls,from_fail,to_fail;
static void* last_publication;static bool publication_pending;
static void synchronize_net(void){++network_graces;}
static void* vzalloc(size_t n){if(alloc_fail)return NULL;void*p=calloc(1,n);assert(p);++allocs;return p;}
static void vfree(void*p){if(p){assert(!publication_pending);++frees;free(p);}}
static int copy_from_user(void*d,const void*s,size_t n){if(++from_calls==from_fail)return 1;memcpy(d,s,n);return 0;}
static int copy_to_user(void*d,const void*s,size_t n){if(++to_calls==to_fail)return 1;memcpy(d,s,n);return 0;}
static void rcu_read_lock(void){++rcu_depth;}
static void rcu_read_unlock(void){assert(rcu_depth);--rcu_depth;}
#define rcu_dereference(p) (assert(rcu_depth),(p))
#define rcu_dereference_protected(p,c) (assert(c),(p))
#define rcu_assign_pointer(p,v) do{assert(!publication_pending);(p)=(v);last_publication=(v);publication_pending=true;}while(0)
static void synchronize_rcu(void){assert(publication_pending&&last_publication&&!rcu_depth);publication_pending=false;++rcu_graces;}

#include <arpa/inet.h>
#include <linux/netfilter/gta3xlwifi_runtime_policy.h>
#include <linux/netfilter/gta3xlwifi_local_network.h>
#include <linux/netfilter/gta3xlwifi_loopback.h>
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
#include <linux/netfilter/gta3xlwifi_packet_stats.h>
static DEFINE_MUTEX(netpolicy_lock);
static struct file *netpolicy_owner_file;
static struct pid *netpolicy_owner_pid;
static bool netpolicy_held = true;

bool gta3xlwifi_netpolicy_held(void)
{
	return smp_load_acquire(&netpolicy_held);
}
EXPORT_SYMBOL_GPL(gta3xlwifi_netpolicy_held);



static u32 fixture_uid,fixture_mask,second_uid,second_mask;
u32 gta3xlwifi_uid_permissions(u32 uid){return uid==fixture_uid?fixture_mask:uid==second_uid?second_mask:0;}
static u32 gta3xlwifi_uid_permissions_features(void){return 7;}
static long gta3xlwifi_uid_permissions_ioctl(unsigned c,unsigned long a){assert(!"unrelated UID store");return -ENOTTY;}
static u32 gta3xlwifi_lna_packet_features(void){return 0;}
static u32 gta3xlwifi_receive_features(void){return 0;}
static u32 gta3xlwifi_egress_features(void){return 0;}
static u32 gta3xlwifi_loopback_features(void){return 0;}
static u32 gta3xlwifi_socket_tables_features(void){return 0;}
static u32 gta3xlwifi_iface_stats_features(void){return 0;}
static u32 gta3xlwifi_packet_stats_features(void){return 0;}
static u32 gta3xlwifi_packet_hooks_features(void){return 0;}
static long gta3xlwifi_lna_ioctl(unsigned c,unsigned long a){assert(!"unrelated LNA store");return -ENOTTY;}
static long gta3xlwifi_loopback_ioctl(unsigned c,unsigned long a){assert(!"unrelated event reader");return -ENOTTY;}
static long gta3xlwifi_iface_stats_ioctl(unsigned c,unsigned long a){assert(!"unrelated interface reader");return -ENOTTY;}
static long gta3xlwifi_packet_stats_ioctl(unsigned c,unsigned long a){assert(!"unrelated packet reader");return -ENOTTY;}
struct runtime_image { u64 revision;u32 flags,count;u32 uids[]; };
static struct runtime_image __rcu *runtime_current;
static bool runtime_lease_configured;
u32 gta3xlwifi_runtime_features(void)
{
#if defined(CONFIG_INET) && defined(CONFIG_IPV6)
    return GTA3XLWIFI_UID_CAP_RUNTIME_POLICY;
#else
    return 0;
#endif
}
EXPORT_SYMBOL_GPL(gta3xlwifi_runtime_features);
bool gta3xlwifi_runtime_configured(void) { return READ_ONCE(runtime_lease_configured); }
EXPORT_SYMBOL_GPL(gta3xlwifi_runtime_configured);
void gta3xlwifi_runtime_invalidate(void) { WRITE_ONCE(runtime_lease_configured,false); }
EXPORT_SYMBOL_GPL(gta3xlwifi_runtime_invalidate);
static bool runtime_contains(const struct runtime_image *image,u32 uid)
{
    u32 low=0,high=image?image->count:0;
    while(low<high){u32 middle=low+(high-low)/2;
        if(image->uids[middle]==uid)return true;
        if(image->uids[middle]<uid)low=middle+1;else high=middle;
    }
    return false;
}
u32 gta3xlwifi_runtime_loopback_flags(void)
{
    const struct runtime_image *image;u32 flags;
    rcu_read_lock();image=rcu_dereference(runtime_current);
    /* Unconfigured traffic cannot be released. Preserve the original guarded
     * enabled/enabled primitive for direct callers until an explicit SET.
     */
    flags=image?image->flags:GTA3XLWIFI_RUNTIME_FLAG_MASK;
    rcu_read_unlock();return flags&3U;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_runtime_loopback_flags);
bool gta3xlwifi_runtime_lna_needs_check(u32 uid)
{
    const struct runtime_image *image;bool result;u32 flags;
    rcu_read_lock();image=rcu_dereference(runtime_current);
    flags=image?image->flags:GTA3XLWIFI_RUNTIME_FLAG_MASK;
    if(flags&GTA3XLWIFI_RUNTIME_PERMISSION_PROPAGATION)
        result=uid!=0&&uid!=1000&&!(gta3xlwifi_uid_permissions(uid)&1U);
    else result=uid%100000U>=10000U&&runtime_contains(image,uid);
    rcu_read_unlock();return result;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_runtime_lna_needs_check);
static long runtime_set(const struct gta3xlwifi_runtime_transfer *t)
{
    struct runtime_image *next,*old;u64 previous;u32 i;long result=0;
    size_t bytes=t->count*sizeof(u32);
    if(!t->revision)return -EINVAL;
    next=vzalloc(sizeof(*next)+bytes);if(!next)return -ENOMEM;
    next->revision=t->revision;next->flags=t->flags;next->count=t->count;
    if(bytes&&copy_from_user(next->uids,(void __user *)(unsigned long)t->entries,bytes)){result=-EFAULT;goto fail;}
    for(i=0;i<next->count;++i)if(next->uids[i]>0x7fffffffU||(i&&next->uids[i-1]>=next->uids[i])){result=-EINVAL;goto fail;}
    old=rcu_dereference_protected(runtime_current,1); /* authenticated owner mutex */
    previous=old?old->revision:0;
    if(old&&next->revision==previous&&next->flags==old->flags&&next->count==old->count&&
       !memcmp(next->uids,old->uids,bytes)){
        WRITE_ONCE(runtime_lease_configured,true);goto fail;
    }
    if(previous==~(u64)0){result=-EOVERFLOW;goto fail;}
    if(next->revision!=previous+1){result=-ESTALE;goto fail;}
    rcu_assign_pointer(runtime_current,next);synchronize_rcu();vfree(old);
    WRITE_ONCE(runtime_lease_configured,true);
    return 0; /* No fallible acknowledgement copy after real publication. */
fail:
    vfree(next);return result;
}
static long runtime_get(struct gta3xlwifi_runtime_transfer *t,void __user *argument)
{
    const struct runtime_image *image=rcu_dereference_protected(runtime_current,1);
    u32 capacity=t->count;u64 expected=t->revision;
    t->revision=image?image->revision:0;t->flags=image?image->flags:0;
    t->count=image?image->count:0;
    t->status=gta3xlwifi_runtime_configured()?GTA3XLWIFI_RUNTIME_CONFIGURED:0;
    if(capacity){
        if(!expected||expected!=t->revision)return -ESTALE;
        if(capacity<t->count){if(copy_to_user(argument,t,sizeof(*t)))return -EFAULT;return -ENOSPC;}
        if(image&&image->count&&copy_to_user((void __user *)(unsigned long)t->entries,image->uids,image->count*sizeof(u32)))return -EFAULT;
    }
    return copy_to_user(argument,t,sizeof(*t))?-EFAULT:0;
}
long gta3xlwifi_runtime_ioctl(unsigned int cmd,unsigned long arg)
{
    struct gta3xlwifi_runtime_transfer t;void __user *argument=(void __user *)arg;
    BUILD_BUG_ON(sizeof(t)!=32);
    if(cmd!=GTA3XLWIFI_RUNTIME_GET&&cmd!=GTA3XLWIFI_RUNTIME_SET)return -ENOTTY;
    if(!arg||copy_from_user(&t,argument,sizeof(t)))return -EFAULT;
    if(t.version!=GTA3XLWIFI_RUNTIME_VERSION||t.count>GTA3XLWIFI_RUNTIME_MAX_BLOCKED_UIDS||
       (!!t.count!=!!t.entries)||t.status||(t.flags&~GTA3XLWIFI_RUNTIME_FLAG_MASK))return -EINVAL;
    if(!gta3xlwifi_runtime_features())return -EOPNOTSUPP;
    if(cmd==GTA3XLWIFI_RUNTIME_SET)return runtime_set(&t);
    if(t.flags)return -EINVAL;
    return runtime_get(&t,argument);
}
EXPORT_SYMBOL_GPL(gta3xlwifi_runtime_ioctl);

static bool netpolicy_privileged(void)
{
	return uid_eq(current_euid(), GLOBAL_ROOT_UID) &&
		ns_capable(&init_user_ns, CAP_NET_ADMIN);
}
static int netpolicy_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	if (!netpolicy_privileged() || !task_tgid(current))
		return -EPERM;
	mutex_lock(&netpolicy_lock);
	if (netpolicy_owner_file) {
		ret = -EBUSY;
	} else {
		WRITE_ONCE(netpolicy_held, true);
		netpolicy_owner_file = file;
		netpolicy_owner_pid = get_pid(task_tgid(current));
		gta3xlwifi_runtime_invalidate();
		/* Drain any packet that entered before the lease was held. */
		synchronize_net();
	}
	mutex_unlock(&netpolicy_lock);
	return ret;
}
static void netpolicy_drop_lease(struct file *file, bool final_release)
{
	mutex_lock(&netpolicy_lock);
	if (netpolicy_owner_file == file &&
	    (final_release || netpolicy_owner_pid == task_tgid(current))) {
		WRITE_ONCE(netpolicy_held, true);
		/* Closing/exit must finish holding before the close completes. */
		synchronize_net();
		gta3xlwifi_runtime_invalidate();
		netpolicy_owner_file = NULL;
		put_pid(netpolicy_owner_pid);
		netpolicy_owner_pid = NULL;
	}
	mutex_unlock(&netpolicy_lock);
}
static int netpolicy_flush(struct file *file, fl_owner_t id)
{
	netpolicy_drop_lease(file, false);
	return 0;
}
static int netpolicy_release(struct inode *inode, struct file *file)
{
	/* Final release can run in a worker or the last inheriting child. */
	netpolicy_drop_lease(file, true);
	return 0;
}
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
static long netpolicy_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	long ret = 0;

	if (cmd == GTA3XLWIFI_UID_FEATURES || cmd == GTA3XLWIFI_UID_SET_IMAGE ||
	    cmd == GTA3XLWIFI_UID_GET_IMAGE || cmd == GTA3XLWIFI_LNA_SET_IMAGE ||
	    cmd == GTA3XLWIFI_LNA_GET_IMAGE || cmd == GTA3XLWIFI_LOOPBACK_GET_EVENTS || cmd == GTA3XLWIFI_IFACE_STATS_GET || cmd == GTA3XLWIFI_STATS_GET_STATE || cmd == GTA3XLWIFI_STATS_READ || cmd == GTA3XLWIFI_STATS_SWAP || cmd == GTA3XLWIFI_STATS_ACK || cmd == GTA3XLWIFI_STATS_EDIT || cmd == GTA3XLWIFI_RUNTIME_GET || cmd == GTA3XLWIFI_RUNTIME_SET)
		return netpolicy_image_ioctl(file, cmd, arg);
	if (cmd != GTA3XLWIFI_NETPOLICY_ABI &&
	    cmd != GTA3XLWIFI_NETPOLICY_HOLD &&
	    cmd != GTA3XLWIFI_NETPOLICY_RELEASE &&
	    cmd != GTA3XLWIFI_NETPOLICY_STATE)
		return -ENOTTY;
	if (arg)
		return -EINVAL;
	if (!netpolicy_privileged())
		return -EPERM;
	mutex_lock(&netpolicy_lock);
	if (!netpolicy_owner_file) {
		ret = -ENOTCONN;
	} else if (netpolicy_owner_file != file ||
		   netpolicy_owner_pid != task_tgid(current)) {
		ret = -EPERM;
	} else if (cmd == GTA3XLWIFI_NETPOLICY_ABI) {
		ret = GTA3XLWIFI_NETPOLICY_VERSION;
	} else if (cmd == GTA3XLWIFI_NETPOLICY_STATE) {
		ret = READ_ONCE(netpolicy_held) ? 1 : 0;
	} else if (cmd == GTA3XLWIFI_NETPOLICY_HOLD) {
		WRITE_ONCE(netpolicy_held, true);
		synchronize_net();
	} else if (!gta3xlwifi_runtime_configured()) {
		ret = -EAGAIN;
	} else if (READ_ONCE(netpolicy_held)) {
		/* A packet may have fetched the old filter table before HOLD.
		 * Drain all such readers while closed before either family opens. */
		synchronize_net();
		smp_store_release(&netpolicy_held, false);
	}
	mutex_unlock(&netpolicy_lock);
	return ret;
}
typedef uint8_t u8;typedef uint16_t u16;
struct net{int unused;};
struct gta3xlwifi_packet{struct in6_addr saddr,daddr;u8 ip_version,ip_proto,tcp_flags;__be16 sport,dport;};
struct gta3xlwifi_socket_peer_tuple{u16 family;u8 protocol;__be16 sport,dport;union{struct{__be32 saddr,daddr;}v4;struct{struct in6_addr saddr,daddr;}v6;}address;};
static bool peer_known=true;static u32 peer_uid;static unsigned lookups,emitted;static bool last_allowed;
static bool gta3xlwifi_socket_peer_uid(struct net*n,int index,const struct gta3xlwifi_socket_peer_tuple*t,u32*uid){assert(n&&index==1&&t);++lookups;if(!peer_known)return false;*uid=peer_uid;return true;}
static void loopback_emit(u32 sender,u32 receiver,bool allowed){assert(sender!=receiver);++emitted;last_allowed=allowed;}
static bool loopback_permissions(u32 sender, u32 receiver)
{
    u32 sender_permissions, receiver_permissions;
    if (sender % 100000U < 10000U || receiver % 100000U < 10000U)
        return true;
    if (sender / 100000U == receiver / 100000U)
        return true;
    sender_permissions = gta3xlwifi_uid_permissions(sender);
    receiver_permissions = gta3xlwifi_uid_permissions(receiver);
    if (((sender_permissions & (1U << 4)) && (sender_permissions & (1U << 5))) ||
        ((receiver_permissions & (1U << 4)) && (receiver_permissions & (1U << 5))))
        return true;
    if (sender % 100000U == receiver % 100000U)
        return !!(sender_permissions & ((1U << 5) | (1U << 6)));
    return !!(sender_permissions & (1U << 5));
}
bool gta3xlwifi_loopback_blocked(struct net *net, u32 ifindex, u32 sender,
                                 const struct gta3xlwifi_packet *packet)
{
    struct gta3xlwifi_socket_peer_tuple tuple = {};
    u32 receiver;
    bool allowed;
    u32 flags = gta3xlwifi_runtime_loopback_flags();
    if (!flags)
        return false;
    if (!net || !packet || ifindex != 1 ||
        (packet->ip_proto != IPPROTO_TCP && packet->ip_proto != IPPROTO_UDP) ||
        (packet->ip_proto == IPPROTO_TCP && !(packet->tcp_flags & 0x02)))
        return false;
    if (packet->ip_version == 4) {
        tuple.family = AF_INET;
        tuple.address.v4.saddr = packet->saddr.s6_addr32[3];
        tuple.address.v4.daddr = packet->daddr.s6_addr32[3];
    } else if (packet->ip_version == 6) {
        tuple.family = AF_INET6;
        tuple.address.v6.saddr = packet->saddr;
        tuple.address.v6.daddr = packet->daddr;
    } else {
        return false;
    }
    tuple.protocol = packet->ip_proto;
    tuple.sport = packet->sport;
    tuple.dport = packet->dport;
    /* Actual referenced peer lookup supplies immutable creator UID; unknown is
     * not UID0. No event for unknown receiver or self, matching A17.
     */
    if (!gta3xlwifi_socket_peer_uid(net, ifindex, &tuple, &receiver) || sender == receiver)
        return false;
    allowed = !(flags & GTA3XLWIFI_RUNTIME_LOOPBACK_CHECKS) ||
              loopback_permissions(sender, receiver);
    if (flags & GTA3XLWIFI_RUNTIME_LOOPBACK_METRICS)
        loopback_emit(sender, receiver, allowed);
    return !allowed;
}

// LINT.IfChange(uid_permission_chunk_type)
// Each UID costs 7 bits (permissions ACCESS_LOCAL_NETWORK / INTERNET /
// UPDATE_DEVICE_STATS or loopback related perms)
// One int64 can store up to 9 UIDs (7 * 9 = 63 bits per int64)
#define PERMISSION_COUNT 7
#define UIDS_PER_INT64 (64 / PERMISSION_COUNT)
#define CHUNK_INT64_COUNT 128
// One chunk can store 128 * 9 = 1152 UIDs using 128 int64
#define CHUNK_UID_COUNT (CHUNK_INT64_COUNT * UIDS_PER_INT64)
#define UID_PERMISSION_MASK ((1 << PERMISSION_COUNT) - 1)
#define PERMISSION_BIT_NONE 0
#define PERMISSION_BIT_ACCESS_LOCAL_NETWORK (1 << 0)
#define PERMISSION_BIT_UPDATE_DEVICE_STATS (1 << 1)
#define PERMISSION_BIT_NO_INTERNET (1 << 2)
// Required for an app to interact with other applications via IP packets on the
// loopback interface.
#define PERMISSION_BIT_USE_LOOPBACK_INTERFACE (1 << 3)
// Required to be able to interact with other applications via IP packets on the
// loopback interface without requiring permissions from the other app
#define PERMISSION_BIT_FORCE_USE_LOOPBACK_INTERFACE (1 << 4)
// Permissions below are required to interact across users/profiles via IP
// packets on the loopback interface.
#define PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL (1 << 5)
#define PERMISSION_BIT_INTERACT_ACROSS_USERS_OR_PROFILES (1 << 6)

enum LoopbackAccessResult {
  LOOPBACK_ACCESS_ALLOWED = 0,
  LOOPBACK_ACCESS_BLOCKED = (1 << 0),
};
#define function static
#define procedure static
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
#define AID_ROOT 0U
#define AID_SYSTEM 1000U
#define BPF_F_CURRENT_NETNS 0
#define TCP_FLAG8_SYN 2
static bool oracle_propagation,oracle_checks,oracle_metrics,oracle_block_value;
static int oracle_block_kind;static unsigned oracle_emitted;static enum LoopbackAccessResult oracle_result;
static bool*bpf_permission_propagation_enabled_map_lookup_elem(const u32*k){assert(!*k);return &oracle_propagation;}
static bool*bpf_local_net_blocked_uid_map_lookup_elem(const u32*k){(void)k;return oracle_block_kind<0?NULL:&oracle_block_value;}
static u32 get_chunk_permissions(u32 uid){return gta3xlwifi_uid_permissions(uid);}
static inline bool is_system_uid(uint32_t uid) {
    // MIN_SYSTEM_UID is AID_ROOT == 0, so uint32_t is *always* >= 0
    // MAX_SYSTEM_UID is AID_NOBODY == 9999, while AID_APP_START == 10000
    return ((uid % AID_USER_OFFSET) < AID_APP_START);
}
static inline bool is_system_or_root(uint32_t uid) {
    return (uid == AID_SYSTEM) || (uid == AID_ROOT);
}
function bool is_local_network_access_blocked(const uint32_t uid) {
    uint32_t mapKey = 0;
    bool *permissionPropagationEnabled =
        bpf_permission_propagation_enabled_map_lookup_elem(&mapKey);
    if (permissionPropagationEnabled && *permissionPropagationEnabled) {
        if (is_system_or_root(uid)) return false;
        if (get_chunk_permissions(uid) & PERMISSION_BIT_ACCESS_LOCAL_NETWORK)
            return false;
    } else {
        // Continue exempting system UIDs for the old map. This branch will be
        // deprecated soon.
        if (is_system_uid(uid)) return false;

        // Uid that is not in the blocked uid map has access to restricted local network
        bool* block_local_net = bpf_local_net_blocked_uid_map_lookup_elem(&uid);
        if (!block_local_net) return false; // uid not found in map
        if (!*block_local_net) return false; // lookup returned 'bool false'
    }
    return true;
}
function bool can_force_loopback(const uint32_t permissions) {
    return (permissions & PERMISSION_BIT_FORCE_USE_LOOPBACK_INTERFACE)
        && (permissions & PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL);
}
function bool uids_have_loopback_permissions(const uint32_t sender_uid,
                                             const uint32_t receiver_uid) {
    // TODO: be more specific about which system uids we should exempt
    if (is_system_uid(sender_uid) || is_system_uid(receiver_uid)) return true;

    bool same_profile =
        sender_uid / AID_USER_OFFSET == receiver_uid / AID_USER_OFFSET;
    if (same_profile) return true;

    uint32_t sender_perms = get_chunk_permissions(sender_uid);
    uint32_t receiver_perms = get_chunk_permissions(receiver_uid);
    if (can_force_loopback(sender_perms)
        || can_force_loopback(receiver_perms)) return true;

    // TODO: check loopback interface permissions for both sender and receiver
    bool same_app_id =
        sender_uid % AID_USER_OFFSET == receiver_uid % AID_USER_OFFSET;
    if (same_app_id) {
        return
            (sender_perms & PERMISSION_BIT_INTERACT_ACROSS_USERS_OR_PROFILES) ||
            (sender_perms & PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL);
    } else {
        return sender_perms & PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL;
    }
}
typedef struct gta3xlwifi_packet SkbIpPacketData;
struct bpf_sock{u32 unused;};static struct bpf_sock oracle_socket;
struct __sk_buff{void*sk;};
struct bpf_sock_tuple{union{struct{__be32 saddr,daddr;__be16 sport,dport;}ipv4;struct{struct in6_addr saddr,daddr;__be16 sport,dport;}ipv6;};};
typedef struct{u64 cached_at_ns;struct in6_addr daddr;__be16 dport;bool result;}LoopbackCache;
typedef struct{u32 uid;LoopbackCache loopback_cache;}SkStorageValue;
static SkStorageValue oracle_storage;
static bool loopback_checks_enabled(void){return oracle_checks;}
static bool loopback_metrics_enabled(void){return oracle_metrics;}
static struct bpf_sock*bpf_sk_lookup_tcp(struct __sk_buff*s,struct bpf_sock_tuple*t,u32 n,int net,int flags){return peer_known?&oracle_socket:NULL;}
static struct bpf_sock*bpf_sk_lookup_udp(struct __sk_buff*s,struct bpf_sock_tuple*t,u32 n,int net,int flags){return peer_known?&oracle_socket:NULL;}
static SkStorageValue*bpf_sk_storage_get(struct bpf_sock*s,int a,int b){assert(s==&oracle_socket);oracle_storage.uid=peer_uid;return &oracle_storage;}
static void bpf_sk_release(struct bpf_sock*s){assert(s==&oracle_socket);}
static void add_loopback_access_event(u32 sender,u32 receiver,enum LoopbackAccessResult result){assert(sender!=receiver);++oracle_emitted;oracle_result=result;}
static u64 bpf_ktime_get_boot_ns(void){return 1000000000ULL;}
#define LOOPBACK_CACHE_EXPIRATION_NS (10ULL*1000ULL*1000ULL)
procedure bool should_block_loopback_access(const SkbIpPacketData *const packet_data,
                                            struct __sk_buff *const skb,
                                            const uint32_t sender_uid,
                                            const bool checks_enabled,
                                            const bool metrics_enabled) {
    struct bpf_sock_tuple sock_tuple = {};
    uint32_t tuple_size;

    if (packet_data->ip_version == 4) {
        // IPv4-mapped-v6
        sock_tuple.ipv4.saddr = packet_data->saddr.s6_addr32[3];
        sock_tuple.ipv4.daddr = packet_data->daddr.s6_addr32[3];
        sock_tuple.ipv4.sport = packet_data->sport;
        sock_tuple.ipv4.dport = packet_data->dport;
        tuple_size = sizeof(sock_tuple.ipv4);
    } else if (packet_data->ip_version == 6) {
        __builtin_memcpy(&sock_tuple.ipv6.saddr, &packet_data->saddr,
                         sizeof(sock_tuple.ipv6.saddr));
        __builtin_memcpy(&sock_tuple.ipv6.daddr, &packet_data->daddr,
                         sizeof(sock_tuple.ipv6.daddr));
        sock_tuple.ipv6.sport = packet_data->sport;
        sock_tuple.ipv6.dport = packet_data->dport;
        tuple_size = sizeof(sock_tuple.ipv6);
    } else {
        return false;
    }

    struct bpf_sock *local_sk;
    if (packet_data->ip_proto == IPPROTO_TCP) {
        local_sk = bpf_sk_lookup_tcp(skb, &sock_tuple, tuple_size,
                                     BPF_F_CURRENT_NETNS, 0);
    } else if (packet_data->ip_proto == IPPROTO_UDP) {
        local_sk = bpf_sk_lookup_udp(skb, &sock_tuple, tuple_size,
                                     BPF_F_CURRENT_NETNS, 0);
    } else {
        return false;
    }
    if (!local_sk) return false;

    SkStorageValue *sks = bpf_sk_storage_get(local_sk, 0, 0);
    const uint32_t receiver_uid = sks ? sks->uid : 0;
    bpf_sk_release(local_sk);
    if (!sks) return false;

    // We don't care about cases where apps are sending loopback traffic to
    // themselves.
    if (sender_uid == receiver_uid) return false;

    bool allowed = true;
    if (checks_enabled) {
        allowed = uids_have_loopback_permissions(sender_uid, receiver_uid);
    }
    if (metrics_enabled) {
        add_loopback_access_event(
                sender_uid, receiver_uid,
                allowed ? LOOPBACK_ACCESS_ALLOWED : LOOPBACK_ACCESS_BLOCKED);
    }
    return !allowed;
}
procedure bool should_block_loopback_access_cached(const SkbIpPacketData *const packet_data,
                                            struct __sk_buff *const skb,
                                            const uint32_t sender_uid) {
    bool checks_enabled = loopback_checks_enabled();
    bool metrics_enabled = loopback_metrics_enabled();
    if (!checks_enabled && !metrics_enabled) return false;

    // TCP connections that already passed loopback access check
    if (packet_data->ip_proto == IPPROTO_TCP
        && !(packet_data->tcp_flags & TCP_FLAG8_SYN)) return false;
    // Remaining TCP will only trigger on SYN to avoid redundant lookups for established connections

    struct bpf_sock* sk = skb->sk;
    if (!sk) return should_block_loopback_access(packet_data, skb, sender_uid,
                                                 checks_enabled, metrics_enabled);
    SkStorageValue *sks = bpf_sk_storage_get(sk, 0, 0);
    if (!sks) return should_block_loopback_access(packet_data, skb, sender_uid,
                                                 checks_enabled, metrics_enabled);

    LoopbackCache *lc = &sks->loopback_cache;
    uint64_t current_ns = bpf_ktime_get_boot_ns();
    if (packet_data->ip_proto == IPPROTO_UDP
        && current_ns - lc->cached_at_ns < LOOPBACK_CACHE_EXPIRATION_NS
        && !__builtin_memcmp(&lc->daddr, &packet_data->daddr, sizeof(struct in6_addr))
        && lc->dport == packet_data->dport) {
        return lc->result;
    }

    bool result = should_block_loopback_access(packet_data, skb, sender_uid,
                                               checks_enabled, metrics_enabled);

    if (packet_data->ip_proto == IPPROTO_UDP) {
        lc->cached_at_ns = current_ns;
        __builtin_memcpy(&lc->daddr, &packet_data->daddr, sizeof(struct in6_addr));
        lc->dport = packet_data->dport;
        lc->result = result;
    }
    return result;
}
static unsigned cases,lna_comparisons,loop_comparisons;
#define T(x) do{if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}++cases;}while(0)
static struct file owner={1},other={2};
static long io(unsigned cmd,void*p){return netpolicy_ioctl(&owner,cmd,(unsigned long)p);}
static struct gta3xlwifi_runtime_transfer tx(u64 rev,u32 flags,u32 n,void*ids){return(struct gta3xlwifi_runtime_transfer){1,n,flags,0,rev,(uintptr_t)ids};}
static struct gta3xlwifi_runtime_transfer metadata(void){struct gta3xlwifi_runtime_transfer t=tx(0,0,0,NULL);assert(!io(GTA3XLWIFI_RUNTIME_GET,&t));return t;}
static void set_mode(u32 flags,u32 n,u32*ids){struct gta3xlwifi_runtime_transfer t=tx((runtime_current?runtime_current->revision:0)+1,flags,n,n?ids:NULL);long result=io(GTA3XLWIFI_RUNTIME_SET,&t);if(result)fprintf(stderr,"SET failed result=%ld rev=%llu flags=%u count=%u held=%d\n",result,(unsigned long long)t.revision,t.flags,t.count,gta3xlwifi_netpolicy_held());assert(!result);}
int main(void){
 T(sizeof(struct gta3xlwifi_runtime_transfer)==32&&GTA3XLWIFI_RUNTIME_GET==0xc0206760&&GTA3XLWIFI_RUNTIME_SET==0x40206761);
 T(!gta3xlwifi_runtime_configured()&&gta3xlwifi_runtime_loopback_flags()==3&&gta3xlwifi_runtime_features()==16384);
 struct gta3xlwifi_runtime_transfer t=tx(1,7,0,NULL);T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-ENOTCONN);T(netpolicy_open(NULL,&owner)==0);T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==-EAGAIN&&gta3xlwifi_netpolicy_held());t=metadata();T(!t.revision&&!t.status&&!t.flags&&!t.count);
 t=tx(0,7,0,NULL);T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EINVAL);set_mode(7,0,NULL);T(gta3xlwifi_runtime_configured());T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==0&&!gta3xlwifi_netpolicy_held());t=tx(2,0,0,NULL);T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EBUSY);T(io(GTA3XLWIFI_NETPOLICY_HOLD,NULL)==0);
 for(unsigned cmd=0;cmd<2;cmd++){unsigned c=cmd?GTA3XLWIFI_RUNTIME_SET:GTA3XLWIFI_RUNTIME_GET;t=tx(2,0,0,NULL);task.euid=1000;T(io(c,&t)==-EPERM);task.euid=0;task.admin=false;T(io(c,&t)==-EPERM);task.admin=true;task.tgid=&child_pid;T(io(c,&t)==-EPERM);task.tgid=&parent_pid;T(netpolicy_ioctl(&other,c,(unsigned long)&t)==-EPERM);T(io(c,NULL)==-EFAULT);}
 u32 ids[]={0,1000,10001,110001,2147483647};set_mode(5,5,ids);t=metadata();T(t.count==5&&t.flags==5&&t.status==1);u32 read_ids[1000]={0};t=tx(t.revision,0,1000,read_ids);T(!io(GTA3XLWIFI_RUNTIME_GET,&t)&&t.count==5&&!memcmp(read_ids,ids,sizeof(ids)));t=tx(t.revision,0,1,read_ids);T(io(GTA3XLWIFI_RUNTIME_GET,&t)==-ENOSPC&&t.count==5);t=tx(1,0,1000,read_ids);T(io(GTA3XLWIFI_RUNTIME_GET,&t)==-ESTALE);
 u64 revision=runtime_current->revision;unsigned graces=rcu_graces;t=tx(revision,5,5,ids);T(!io(GTA3XLWIFI_RUNTIME_SET,&t)&&rcu_graces==graces);T(netpolicy_flush(&owner,NULL)==0&&!gta3xlwifi_runtime_configured());T(netpolicy_open(NULL,&owner)==0&&!gta3xlwifi_runtime_configured());t=metadata();T(t.revision==revision&&t.flags==5&&t.status==0);T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==-EAGAIN);t=tx(revision,5,5,ids);T(!io(GTA3XLWIFI_RUNTIME_SET,&t)&&gta3xlwifi_runtime_configured()&&rcu_graces==graces);
 for(unsigned bad=0;bad<8;bad++){t=tx(revision+1,5,5,ids);u32 saved=ids[1];switch(bad){case 0:t.version=2;break;case 1:t.flags=8;break;case 2:t.status=1;break;case 3:t.count=1001;break;case 4:t.entries=0;break;case 5:t.revision=revision+2;break;case 6:ids[1]=ids[0];break;case 7:ids[1]=UINT32_MAX;break;}T(io(GTA3XLWIFI_RUNTIME_SET,&t)==(bad==5?-ESTALE:-EINVAL)&&runtime_current->revision==revision);ids[1]=saved;}
 t=tx(revision+1,0,0,NULL);alloc_fail=1;T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-ENOMEM&&runtime_current->revision==revision);alloc_fail=0;from_fail=from_calls+1;T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EFAULT);from_fail=0;t=tx(revision+1,5,5,ids);from_fail=from_calls+2;T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EFAULT&&runtime_current->revision==revision);from_fail=0;t=tx(0,0,0,NULL);to_fail=to_calls+1;T(io(GTA3XLWIFI_RUNTIME_GET,&t)==-EFAULT);to_fail=0;
 const u32 uids[]={0,1,999,1000,1001,9999,10000,10001,65534,99999,100000,101000,109999,110000,110001,2147483647};
 for(u32 flags=0;flags<8;flags++)for(int blocked=-1;blocked<=1;blocked++){
  oracle_propagation=flags&4;oracle_block_kind=blocked;oracle_block_value=blocked==1;set_mode(flags,blocked==1?16:0,(u32*)uids);T(metadata().flags==flags);
  for(unsigned u=0;u<16;u++)for(u32 mask=0;mask<128;mask++){fixture_uid=uids[u];fixture_mask=mask;second_uid=UINT32_MAX;second_mask=0;assert(gta3xlwifi_runtime_lna_needs_check(uids[u])==is_local_network_access_blocked(uids[u]));++lna_comparisons;}
 }
 struct net net={0};struct gta3xlwifi_packet packet={.ip_version=4,.ip_proto=IPPROTO_UDP,.tcp_flags=2};struct __sk_buff skb={0};const u32 pairs[][2]={{10001,110001},{10001,110002},{110001,10001},{0,110001},{101000,110001},{10001,10002}};
 for(u32 flags=0;flags<8;flags++){set_mode(flags,0,NULL);oracle_checks=flags&1;oracle_metrics=flags&2;
  for(unsigned pair=0;pair<6;pair++)for(u32 senderMask=0;senderMask<128;senderMask++)for(u32 receiverMask=0;receiverMask<128;receiverMask++){
   fixture_uid=pairs[pair][0];second_uid=peer_uid=pairs[pair][1];fixture_mask=senderMask;second_mask=receiverMask;peer_known=true;emitted=oracle_emitted=lookups=0;
   bool expected=should_block_loopback_access_cached(&packet,&skb,fixture_uid);bool actual=gta3xlwifi_loopback_blocked(&net,1,fixture_uid,&packet);
   assert(actual==expected&&emitted==oracle_emitted&&(!emitted||(last_allowed==(oracle_result==LOOPBACK_ACCESS_ALLOWED)))&&(flags&3?lookups==1:lookups==0));++loop_comparisons;
  }
  for(unsigned fault=0;fault<6;fault++){packet.ip_version=4;packet.ip_proto=IPPROTO_UDP;packet.tcp_flags=2;peer_known=true;peer_uid=second_uid=110002;fixture_uid=10001;fixture_mask=second_mask=0;unsigned index=1;switch(fault){case 0:peer_known=false;break;case 1:peer_uid=fixture_uid;break;case 2:packet.ip_version=0;break;case 3:packet.ip_proto=IPPROTO_GRE;break;case 4:packet.ip_proto=IPPROTO_TCP;packet.tcp_flags=0;break;case 5:index=17;break;}emitted=0;T(!gta3xlwifi_loopback_blocked(&net,index,fixture_uid,&packet)&&!emitted);}
  packet.ip_version=4;packet.ip_proto=IPPROTO_UDP;packet.tcp_flags=2;
 }
 runtime_current->revision=UINT64_MAX;t=tx(1,7,0,NULL);T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EOVERFLOW);t=tx(UINT64_MAX,runtime_current->flags,0,NULL);T(!io(GTA3XLWIFI_RUNTIME_SET,&t));T(netpolicy_release(NULL,&owner)==0&&!gta3xlwifi_runtime_configured()&&gta3xlwifi_netpolicy_held());
 printf("passed_cases=%u LNA_comparisons=%u loopback_comparisons=%u\n",cases,lna_comparisons,loop_comparisons);return 0;
}
