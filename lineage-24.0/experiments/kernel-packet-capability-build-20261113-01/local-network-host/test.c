
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
static int alloc_fail,alloc_attempt,alloc_fail_at,from_calls,to_calls,from_fail,to_fail;
static void* last_publication;static bool publication_pending;
static void synchronize_net(void){++network_graces;}
static void* vzalloc(size_t n){if(++alloc_attempt==alloc_fail_at||alloc_fail)return NULL;void*p=calloc(1,n);assert(p);++allocs;return p;}
static void vfree(void*p){if(p){assert(!publication_pending);++frees;free(p);}}
static int copy_from_user(void*d,const void*s,size_t n){if(++from_calls==from_fail)return 1;memcpy(d,s,n);return 0;}
static int copy_to_user(void*d,const void*s,size_t n){if(++to_calls==to_fail)return 1;memcpy(d,s,n);return 0;}
static void rcu_read_lock(void){++rcu_depth;}
static void rcu_read_unlock(void){assert(rcu_depth);--rcu_depth;}
#define rcu_dereference(p) (assert(rcu_depth),(p))
#define rcu_dereference_protected(p,c) (assert(c),(p))
#define rcu_assign_pointer(p,v) do{assert(!publication_pending);(p)=(v);last_publication=(v);publication_pending=true;}while(0)
static void synchronize_rcu(void){assert(publication_pending&&last_publication&&!rcu_depth);publication_pending=false;++rcu_graces;}

#include <netinet/in.h>
#include <linux/netfilter/gta3xlwifi_local_network.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint16_t __be16;
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))

static u32 gta3xlwifi_lna_packet_features(void){return 0;} /* registration tested separately */

#include <linux/netfilter/gta3xlwifi_loopback.h>
static u32 gta3xlwifi_loopback_features(void){return 0;}
static long gta3xlwifi_loopback_ioctl(unsigned int cmd,unsigned long arg){(void)cmd;(void)arg;assert(!"legacy primitive test entered loopback stream");return -ENOTTY;}

static u32 gta3xlwifi_receive_features(void){return 0;} /* receive registration tested separately */

#include <linux/netfilter/gta3xlwifi_iface_stats.h>
static unsigned gta3xlwifi_iface_stats_features(void){return 0;} /* actual producer tested separately */
static long gta3xlwifi_iface_stats_ioctl(unsigned int c,unsigned long a){(void)c;(void)a;assert(!"legacy fixture entered interface snapshot");return -ENOTTY;}

#include <linux/netfilter/gta3xlwifi_packet_stats.h>
static unsigned gta3xlwifi_packet_stats_features(void){return 0;} /* actual storage tested separately */
static long gta3xlwifi_packet_stats_ioctl(unsigned int c,unsigned long a){(void)c;(void)a;assert(!"legacy fixture entered packet storage");return -ENOTTY;}

static u32 gta3xlwifi_socket_tables_features(void){return 0;} /* real table registration tested separately */

static u32 gta3xlwifi_egress_features(void){return 0;} /* output hooks tested separately */

static unsigned gta3xlwifi_packet_hooks_features(void){return 0;} /* compiled primitive tested separately */

static DEFINE_MUTEX(netpolicy_lock);
static struct file *netpolicy_owner_file;
static struct pid *netpolicy_owner_pid;
static bool netpolicy_held = true;

bool gta3xlwifi_netpolicy_held(void)
{
	return smp_load_acquire(&netpolicy_held);
}
EXPORT_SYMBOL_GPL(gta3xlwifi_netpolicy_held);



struct gta3xlwifi_uid_image {
    u64 revision;
    u32 count;
    struct gta3xlwifi_uid_permission_entry entries[];
};
static struct gta3xlwifi_uid_image __rcu *uid_image;

static u32 uid_image_lookup(const struct gta3xlwifi_uid_image *image, u32 uid)
{
    u32 low = 0, high = image ? image->count : 0;
    while (low < high) {
        u32 middle = low + (high - low) / 2;
        const struct gta3xlwifi_uid_permission_entry *entry = &image->entries[middle];
        if (entry->uid == uid)
            return entry->permissions;
        if (entry->uid < uid)
            low = middle + 1;
        else
            high = middle;
    }
    return 0; /* Actual A17 chunk default NONE; NoInternet is a negative bit. */
}

u32 gta3xlwifi_uid_permissions(u32 uid)
{
    u32 permissions;
    rcu_read_lock();
    permissions = uid_image_lookup(rcu_dereference(uid_image), uid);
    rcu_read_unlock();
    return permissions;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_uid_permissions);

int gta3xlwifi_uid_inet_create_check(void)
{
    u32 uid = from_kuid(&init_user_ns, current_uid());
    bool control = uid % 100000 < 10000;
    int result = 0;
    if (!control && gta3xlwifi_netpolicy_held())
        control = ns_capable(&init_user_ns, CAP_NET_ADMIN);
    rcu_read_lock();
    if (uid_image_lookup(rcu_dereference(uid_image), uid) & GTA3XLWIFI_UID_NO_INTERNET)
        result = -EPERM;
    else if (gta3xlwifi_netpolicy_held() && !control)
        result = -EAGAIN;
    rcu_read_unlock();
    /* Holding a transaction prevents unprivileged new fds during transient
     * grants/rollback. Trusted core/control tasks may create control sockets
     * while held, but NEVER bypass an actual NoInternet denial.
     */
    return result;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_uid_inet_create_check);

u32 gta3xlwifi_uid_permissions_features(void)
{
    u32 features = GTA3XLWIFI_UID_CAP_IMAGE;
#ifdef CONFIG_INET
    features |= GTA3XLWIFI_UID_CAP_CREATE4;
#endif
#if IS_ENABLED(CONFIG_IPV6)
    features |= GTA3XLWIFI_UID_CAP_CREATE6;
#endif
    return features;
}

static long uid_image_set(const struct gta3xlwifi_uid_permission_transfer *transfer)
{
    struct gta3xlwifi_uid_image *next, *old;
    size_t bytes = transfer->count * sizeof(next->entries[0]);
    u64 previous;
    u32 i;
    long result = 0;

    next = vzalloc(sizeof(*next) + bytes);
    if (!next)
        return -ENOMEM;
    next->count = transfer->count;
    next->revision = transfer->revision;
    if (bytes && copy_from_user(next->entries,
            (void __user *)(unsigned long)transfer->entries, bytes)) {
        result = -EFAULT;
        goto fail;
    }
    for (i = 0; i < next->count; ++i) {
        const struct gta3xlwifi_uid_permission_entry *entry = &next->entries[i];
        if (entry->uid > GTA3XLWIFI_UID_IMAGE_MAX_UID || !entry->permissions ||
            (entry->permissions & ~GTA3XLWIFI_UID_PERMISSION_MASK) ||
            (i && next->entries[i - 1].uid >= entry->uid)) {
            result = -EINVAL;
            goto fail;
        }
    }
    old = rcu_dereference_protected(uid_image, 1); /* owner dispatch mutex held */
    previous = old ? old->revision : 0;
    if (old && next->revision == previous && next->count == old->count &&
        !memcmp(next->entries, old->entries, bytes))
        goto fail; /* Idempotent acknowledgement, no replacement. */
    if (previous == ~0ULL) {
        result = -EOVERFLOW;
        goto fail;
    }
    if (next->revision != previous + 1) {
        result = -ESTALE;
        goto fail;
    }
    rcu_assign_pointer(uid_image, next);
    synchronize_rcu();
    vfree(old);
    return 0; /* No fallible operation/acknowledgement copy after publication. */
fail:
    vfree(next);
    return result;
}

static long uid_image_get(struct gta3xlwifi_uid_permission_transfer *transfer,
                          void __user *argument)
{
    struct gta3xlwifi_uid_image *image = rcu_dereference_protected(uid_image, 1);
    u32 capacity = transfer->count;
    u64 expected = transfer->revision;
    transfer->count = image ? image->count : 0;
    transfer->revision = image ? image->revision : 0;
    if (capacity) {
        if (!expected || expected != transfer->revision)
            return -ESTALE;
        if (capacity < transfer->count) {
            if (copy_to_user(argument, transfer, sizeof(*transfer)))
                return -EFAULT;
            return -ENOSPC;
        }
        if (image && image->count && copy_to_user(
                (void __user *)(unsigned long)transfer->entries, image->entries,
                image->count * sizeof(image->entries[0])))
            return -EFAULT;
    }
    if (copy_to_user(argument, transfer, sizeof(*transfer)))
        return -EFAULT;
    return 0;
}

long gta3xlwifi_uid_permissions_ioctl(unsigned int cmd, unsigned long arg)
{
    struct gta3xlwifi_uid_permission_transfer transfer;
    void __user *argument = (void __user *)arg;
    BUILD_BUG_ON(sizeof(transfer) != 24);
    BUILD_BUG_ON(sizeof(struct gta3xlwifi_uid_permission_entry) != 8);
    if (cmd != GTA3XLWIFI_UID_SET_IMAGE && cmd != GTA3XLWIFI_UID_GET_IMAGE)
        return -ENOTTY;
    if (!arg || copy_from_user(&transfer, argument, sizeof(transfer)))
        return -EFAULT;
    if (transfer.version != GTA3XLWIFI_UID_IMAGE_VERSION ||
        transfer.count > GTA3XLWIFI_UID_IMAGE_MAX_ENTRIES ||
        (!!transfer.count != !!transfer.entries))
        return -EINVAL;
    if (cmd == GTA3XLWIFI_UID_SET_IMAGE)
        return uid_image_set(&transfer);
    return uid_image_get(&transfer, argument);
}
#define LNA_NONE (-1)
struct lna_node {
    u8 key[GTA3XLWIFI_LNA_KEY_BYTES];
    u16 bits;
    u8 has_value, value;
    int child[2];
};
struct lna_table {
    u32 count, nodes_count;
    int root;
    struct gta3xlwifi_lna_entry *entries;
    struct lna_node *nodes;
};
struct lna_image {
    u64 revision;
    struct lna_table network, host;
};
static struct lna_image __rcu *lna_current;

static bool lna_prefix(const u8 *a, const u8 *b, u32 bits)
{
    u32 bytes = bits / 8, remainder = bits % 8;
    return !memcmp(a, b, bytes) &&
        (!remainder || !((a[bytes] ^ b[bytes]) & (0xffU << (8 - remainder))));
}
static unsigned int lna_bit(const u8 *key, unsigned int bit)
{
    return (key[bit / 8] >> (7 - bit % 8)) & 1;
}
static void lna_canonical(u8 *key, u32 bits)
{
    u32 bytes = bits / 8;
    if (bits % 8) {
        key[bytes] &= 0xffU << (8 - bits % 8);
        ++bytes;
    }
    memset(key + bytes, 0, GTA3XLWIFI_LNA_KEY_BYTES - bytes);
}
static int lna_node_new(struct lna_table *table, const u8 *key, u32 bits,
                        bool has_value, bool value)
{
    struct lna_node *node;
    int index;
    if (table->nodes_count >= 2 * table->count)
        return -E2BIG;
    index = table->nodes_count++;
    node = &table->nodes[index];
    memcpy(node->key, key, sizeof(node->key));
    lna_canonical(node->key, bits);
    node->bits = bits;
    node->has_value = has_value;
    node->value = value;
    node->child[0] = node->child[1] = LNA_NONE;
    return index;
}
static int lna_insert(struct lna_table *table, const struct gta3xlwifi_lna_entry *entry)
{
    int *link = &table->root;
    while (*link != LNA_NONE) {
        struct lna_node *node = &table->nodes[*link];
        u32 common = 0, limit = min_t(u32, node->bits, entry->prefix_bits);
        int branch, leaf, previous = *link;
        while (common < limit && lna_bit(node->key, common) == lna_bit(entry->key, common))
            ++common;
        if (common < node->bits) {
            branch = lna_node_new(table, entry->key, common,
                                   common == entry->prefix_bits, entry->allowed);
            if (branch < 0)
                return branch;
            table->nodes[branch].child[lna_bit(node->key, common)] = previous;
            if (common < entry->prefix_bits) {
                leaf = lna_node_new(table, entry->key, entry->prefix_bits, true, entry->allowed);
                if (leaf < 0)
                    return leaf;
                table->nodes[branch].child[lna_bit(entry->key, common)] = leaf;
            }
            *link = branch;
            return 0;
        }
        if (common == entry->prefix_bits) {
            if (node->has_value)
                return -EINVAL;
            node->has_value = true;
            node->value = entry->allowed;
            return 0;
        }
        link = &node->child[lna_bit(entry->key, node->bits)];
    }
    *link = lna_node_new(table, entry->key, entry->prefix_bits, true, entry->allowed);
    return *link < 0 ? *link : 0;
}
static bool lna_lookup(const struct lna_table *table, const u8 *key, bool *value)
{
    int index = table->root;
    bool found = false;
    while (index != LNA_NONE) {
        const struct lna_node *node = &table->nodes[index];
        if (!lna_prefix(node->key, key, node->bits))
            break;
        if (node->has_value) {
            *value = node->value;
            found = true;
        }
        if (node->bits == GTA3XLWIFI_LNA_KEY_BITS)
            break;
        index = node->child[lna_bit(key, node->bits)];
    }
    return found;
}
static void lna_free(struct lna_image *image)
{
    if (!image)
        return;
    vfree(image->network.entries);
    vfree(image->network.nodes);
    vfree(image->host.entries);
    vfree(image->host.nodes);
    vfree(image);
}
static int lna_prepare(struct lna_table *table, u32 count, u64 pointer)
{
    u32 i;
    int result;
    table->root = LNA_NONE;
    table->count = count;
    if (!count)
        return 0;
    table->entries = vzalloc(count * sizeof(*table->entries));
    table->nodes = vzalloc(2 * count * sizeof(*table->nodes));
    if (!table->entries || !table->nodes)
        return -ENOMEM;
    if (copy_from_user(table->entries, (void __user *)(unsigned long)pointer,
                       count * sizeof(*table->entries)))
        return -EFAULT;
    for (i = 0; i < count; ++i) {
        const struct gta3xlwifi_lna_entry *e = &table->entries[i];
        u8 canonical[GTA3XLWIFI_LNA_KEY_BYTES];
        if (e->prefix_bits > GTA3XLWIFI_LNA_KEY_BITS || e->allowed > 1 ||
            e->reserved[0] || e->reserved[1] || e->reserved[2])
            return -EINVAL;
        memcpy(canonical, e->key, sizeof(canonical));
        lna_canonical(canonical, e->prefix_bits);
        if (memcmp(canonical, e->key, sizeof(canonical)))
            return -EINVAL;
        if (i) {
            const struct gta3xlwifi_lna_entry *previous = e - 1;
            if (previous->prefix_bits > e->prefix_bits ||
                (previous->prefix_bits == e->prefix_bits &&
                 memcmp(previous->key, e->key, sizeof(e->key)) >= 0))
                return -EINVAL;
        }
        result = lna_insert(table, e);
        if (result)
            return result;
    }
    return 0;
}
static bool lna_same(const struct lna_table *a, const struct lna_table *b)
{
    return a->count == b->count && (!a->count ||
        !memcmp(a->entries, b->entries, a->count * sizeof(*a->entries)));
}
static long lna_set(const struct gta3xlwifi_lna_transfer *transfer)
{
    struct lna_image *next = vzalloc(sizeof(*next)), *old;
    u64 previous;
    int result;
    if (!next)
        return -ENOMEM;
    result = lna_prepare(&next->network, transfer->network_count, transfer->network_entries);
    if (!result)
        result = lna_prepare(&next->host, transfer->host_count, transfer->host_entries);
    if (result)
        goto fail;
    next->revision = transfer->revision;
    old = rcu_dereference_protected(lna_current, 1); /* exclusive owner mutex */
    previous = old ? old->revision : 0;
    if (old && previous == next->revision && lna_same(&next->network, &old->network) &&
        lna_same(&next->host, &old->host))
        goto fail;
    result = previous == ~0ULL ? -EOVERFLOW :
        next->revision != previous + 1 ? -ESTALE : 0;
    if (result)
        goto fail;
    rcu_assign_pointer(lna_current, next);
    synchronize_rcu();
    lna_free(old);
    return 0;
fail:
    lna_free(next);
    return result;
}
static long lna_get(struct gta3xlwifi_lna_transfer *transfer, void __user *argument)
{
    const struct lna_image *image = rcu_dereference_protected(lna_current, 1);
    u32 network_capacity = transfer->network_count, host_capacity = transfer->host_count;
    u64 expected = transfer->revision;
    transfer->network_count = image ? image->network.count : 0;
    transfer->host_count = image ? image->host.count : 0;
    transfer->revision = image ? image->revision : 0;
    if (network_capacity || host_capacity) {
        if (!expected || expected != transfer->revision)
            return -ESTALE;
        if (network_capacity < transfer->network_count || host_capacity < transfer->host_count) {
            if (copy_to_user(argument, transfer, sizeof(*transfer)))
                return -EFAULT;
            return -ENOSPC;
        }
        if ((transfer->network_count && copy_to_user(
                 (void __user *)(unsigned long)transfer->network_entries, image->network.entries,
                 transfer->network_count * sizeof(*image->network.entries))) ||
            (transfer->host_count && copy_to_user(
                 (void __user *)(unsigned long)transfer->host_entries, image->host.entries,
                 transfer->host_count * sizeof(*image->host.entries))))
            return -EFAULT;
    }
    return copy_to_user(argument, transfer, sizeof(*transfer)) ? -EFAULT : 0;
}
long gta3xlwifi_lna_ioctl(unsigned int cmd, unsigned long arg)
{
    struct gta3xlwifi_lna_transfer transfer;
    void __user *argument = (void __user *)arg;
    BUILD_BUG_ON(sizeof(transfer) != 40);
    BUILD_BUG_ON(sizeof(struct gta3xlwifi_lna_entry) != 32);
    if (cmd != GTA3XLWIFI_LNA_SET_IMAGE && cmd != GTA3XLWIFI_LNA_GET_IMAGE)
        return -ENOTTY;
    if (!arg || copy_from_user(&transfer, argument, sizeof(transfer)))
        return -EFAULT;
    if (transfer.version != GTA3XLWIFI_LNA_VERSION || transfer.reserved ||
        transfer.network_count > GTA3XLWIFI_LNA_MAX_ENTRIES ||
        transfer.host_count > GTA3XLWIFI_LNA_MAX_ENTRIES ||
        (!!transfer.network_count != !!transfer.network_entries) ||
        (!!transfer.host_count != !!transfer.host_entries))
        return -EINVAL;
    return cmd == GTA3XLWIFI_LNA_SET_IMAGE ? lna_set(&transfer) : lna_get(&transfer, argument);
}

bool gta3xlwifi_lna_blocked(u32 uid, u32 if_index, const struct in6_addr *remote,
                           u16 protocol, __be16 remote_port)
{
    const struct lna_image *image;
    u8 network_key[24], host_key[24];
    bool value = false, blocked = false;
    /* Exact migrated A17 exemption: literal0/1000, NOT appId/core range. */
    if (uid == 0 || uid == 1000 || (gta3xlwifi_uid_permissions(uid) & 1U))
        return false;
    if (!remote)
        return true; /* Invalid internal caller must not turn denial into success. */
    memcpy(network_key, &if_index, 4);
    memcpy(network_key + 4, remote, 16);
    memcpy(network_key + 20, &protocol, 2);
    memcpy(network_key + 22, &remote_port, 2);
    memcpy(host_key, &uid, 4);
    memcpy(host_key + 4, &if_index, 4);
    memcpy(host_key + 8, remote, 16);
    rcu_read_lock();
    image = rcu_dereference(lna_current);
    if (image && lna_lookup(&image->network, network_key, &value) && !value)
        blocked = !lna_lookup(&image->host, host_key, &value) || !value;
    rcu_read_unlock();
    return blocked;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_lna_blocked);

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
	    cmd != GTA3XLWIFI_LNA_GET_IMAGE && cmd != GTA3XLWIFI_LOOPBACK_GET_EVENTS && cmd != GTA3XLWIFI_IFACE_STATS_GET && cmd != GTA3XLWIFI_STATS_GET_STATE && cmd != GTA3XLWIFI_STATS_READ && cmd != GTA3XLWIFI_STATS_SWAP && cmd != GTA3XLWIFI_STATS_ACK && cmd != GTA3XLWIFI_STATS_EDIT)
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
		      gta3xlwifi_socket_tables_features() | gta3xlwifi_iface_stats_features() | gta3xlwifi_packet_stats_features() | gta3xlwifi_packet_hooks_features();
	else if ((cmd == GTA3XLWIFI_UID_SET_IMAGE || cmd == GTA3XLWIFI_LNA_SET_IMAGE) &&
	         !READ_ONCE(netpolicy_held))
		ret = -EBUSY;
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
	    cmd == GTA3XLWIFI_LNA_GET_IMAGE || cmd == GTA3XLWIFI_LOOPBACK_GET_EVENTS || cmd == GTA3XLWIFI_IFACE_STATS_GET || cmd == GTA3XLWIFI_STATS_GET_STATE || cmd == GTA3XLWIFI_STATS_READ || cmd == GTA3XLWIFI_STATS_SWAP || cmd == GTA3XLWIFI_STATS_ACK || cmd == GTA3XLWIFI_STATS_EDIT)
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
	} else if (READ_ONCE(netpolicy_held)) {
		/* A packet may have fetched the old filter table before HOLD.
		 * Drain all such readers while closed before either family opens. */
		synchronize_net();
		smp_store_release(&netpolicy_held, false);
	}
	mutex_unlock(&netpolicy_lock);
	return ret;
}

#define function static
#define AID_ROOT 0U
#define AID_SYSTEM 1000U
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
#define PERMISSION_BIT_ACCESS_LOCAL_NETWORK (1 << 0)
typedef struct {
    // Longest prefix match length in bits (value from 0 to 192).
    uint32_t lpm_bitlen;
    uint32_t if_index;
    // IPv4 uses IPv4-mapped IPv6 address format.
    struct in6_addr remote_ip6;
    // u16 instead of u8 to avoid padding due to alignment requirement.
    uint16_t protocol;
    __be16 remote_port;
} LocalNetAccessKey;
typedef struct {
    // Longest prefix match length in bits (value from 0 to 192).
    uint32_t lpm_bitlen;
    uint32_t uid;
    uint32_t if_index;
    // IPv4 uses IPv4-mapped IPv6 address format.
    struct in6_addr remote_ip6;
} LocalNetUidHostAllowlistKey;
static struct gta3xlwifi_lna_entry *onetwork,*ohost;
static u32 oncount,ohcount;
static bool oracle_propagation=true,omvalue,ohvalue;
static const struct gta3xlwifi_lna_entry* slow_lpm(const struct gta3xlwifi_lna_entry*e,u32 count,const u8*key){
 const struct gta3xlwifi_lna_entry*best=NULL;
 for(u32 i=0;i<count;i++){
  bool equal=true;for(u32 bit=0;bit<e[i].prefix_bits;bit++)if(((key[bit/8]>>(7-bit%8))&1)!=((e[i].key[bit/8]>>(7-bit%8))&1)){equal=false;break;}
  if(equal&&(!best||e[i].prefix_bits>best->prefix_bits))best=&e[i];
 }return best;
}
static bool* bpf_local_net_access_map_lookup_elem(const LocalNetAccessKey*k){assert(k->lpm_bitlen==192);const struct gta3xlwifi_lna_entry*e=slow_lpm(onetwork,oncount,(const u8*)&k->if_index);if(!e)return NULL;omvalue=e->allowed;return &omvalue;}
static bool* bpf_local_net_uid_host_allowlist_map_lookup_elem(const LocalNetUidHostAllowlistKey*k){assert(k->lpm_bitlen==192);const struct gta3xlwifi_lna_entry*e=slow_lpm(ohost,ohcount,(const u8*)&k->uid);if(!e)return NULL;ohvalue=e->allowed;return &ohvalue;}
static bool* bpf_permission_propagation_enabled_map_lookup_elem(const u32*k){assert(*k==0);return &oracle_propagation;}
static bool* bpf_local_net_blocked_uid_map_lookup_elem(const u32*k){(void)k;assert(!"unselected old permission branch");return NULL;}
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
function bool is_local_net_access_allowed(const LocalNetAccessKey *query_key, const uint32_t uid) {
    bool* v = bpf_local_net_access_map_lookup_elem(query_key);
    if (!v || *v) {
        return true;
    }
    LocalNetUidHostAllowlistKey allowlist_query_key = {
        .lpm_bitlen =
            8 * (sizeof(uid) + sizeof(query_key->if_index) + sizeof(query_key->remote_ip6)),
        .uid = uid,
        .if_index = query_key->if_index,
        .remote_ip6 = query_key->remote_ip6,
    };
    v = bpf_local_net_uid_host_allowlist_map_lookup_elem(&allowlist_query_key);
    return v && *v;
}
static bool oracle_blocked(u32 uid,u32 index,const struct in6_addr*remote,u16 protocol,__be16 port){
 LocalNetAccessKey key={.lpm_bitlen=192,.if_index=index,.remote_ip6=*remote,.protocol=protocol,.remote_port=port};
 return is_local_network_access_blocked(uid)&&!is_local_net_access_allowed(&key,uid);
}


static unsigned cases,comparisons;
#define T(x) do{if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}++cases;}while(0)
static struct file owner={1},foreign={2};
static long io(unsigned cmd,void*arg){from_calls=to_calls=alloc_attempt=0;return netpolicy_ioctl(&owner,cmd,(unsigned long)arg);}
static struct gta3xlwifi_lna_transfer tx(u64 rev,u32 nc,void*n,u32 hc,void*host){return(struct gta3xlwifi_lna_transfer){1,nc,hc,0,rev,(uintptr_t)n,(uintptr_t)host};}
static int compare(const void*a,const void*b){const struct gta3xlwifi_lna_entry*x=a,*y=b;if(x->prefix_bits!=y->prefix_bits)return x->prefix_bits<y->prefix_bits?-1:1;return memcmp(x->key,y->key,24);}
static u32 state=0x12345678;static u32 random32(void){state^=state<<13;state^=state>>17;state^=state<<5;return state;}
static void reference_image(struct gta3xlwifi_lna_entry*n,u32 nc,struct gta3xlwifi_lna_entry*host,u32 hc){onetwork=n;oncount=nc;ohost=host;ohcount=hc;}
static void check_decision(u32 uid,u32 index,const struct in6_addr*ip,u16 proto,__be16 port){assert(gta3xlwifi_lna_blocked(uid,index,ip,proto,port)==oracle_blocked(uid,index,ip,proto,port));++comparisons;}
int main(void){
 _Static_assert(sizeof(LocalNetAccessKey)==28&&sizeof(LocalNetUidHostAllowlistKey)==28,"actual A17 layouts");
 T(sizeof(struct gta3xlwifi_lna_transfer)==40&&sizeof(struct gta3xlwifi_lna_entry)==32);
 T(GTA3XLWIFI_LNA_SET_IMAGE==0x40286757&&GTA3XLWIFI_LNA_GET_IMAGE==0xc0286758);
 struct gta3xlwifi_lna_entry n[2]={{.prefix_bits=0,.allowed=0},{.prefix_bits=192,.allowed=1}},host[1]={{.prefix_bits=192,.allowed=1}};
 u32 uidval=10001,index=7;u16 proto=17;__be16 port=htons(5353);struct in6_addr ip={0};ip.s6_addr[0]=0x20;ip.s6_addr[1]=1;ip.s6_addr[2]=0x0d;ip.s6_addr[3]=0xb8;
 memcpy(n[1].key,&index,4);memcpy(n[1].key+4,&ip,16);memcpy(n[1].key+20,&proto,2);memcpy(n[1].key+22,&port,2);
 memcpy(host[0].key,&uidval,4);memcpy(host[0].key+4,&index,4);memcpy(host[0].key+8,&ip,16);
 struct gta3xlwifi_lna_transfer t=tx(1,2,n,1,host),q=tx(0,0,NULL,0,NULL);
 T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ENOTCONN);T(netpolicy_open(NULL,&owner)==0);T(io(GTA3XLWIFI_UID_FEATURES,NULL)==15&&gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==0&&q.revision==0&&q.network_count==0&&q.host_count==0);
 for(unsigned i=0;i<2;i++){unsigned cmd=i?GTA3XLWIFI_LNA_GET_IMAGE:GTA3XLWIFI_LNA_SET_IMAGE;
  task.euid=1000;T(io(cmd,&t)==-EPERM);task.euid=0;task.admin=false;T(io(cmd,&t)==-EPERM);task.admin=true;
  task.tgid=&child_pid;T(io(cmd,&t)==-EPERM);task.tgid=&parent_pid;T(netpolicy_ioctl(&foreign,cmd,(unsigned long)&t)==-EPERM);
 }
 T(io(GTA3XLWIFI_LNA_SET_IMAGE,NULL)==-EFAULT);T(io(GTA3XLWIFI_LNA_GET_IMAGE,NULL)==-EFAULT);T(io(0x6757,NULL)==-ENOTTY);T(io(0x6759,NULL)==-ENOTTY);
 T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0&&lna_current->revision==1&&rcu_graces==1);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0&&rcu_graces==1);
 reference_image(n,2,host,1);check_decision(10001,index,&ip,proto,port);check_decision(10002,index,&ip,proto,port);check_decision(10002,index,&ip,6,port);check_decision(10001,index,&ip,6,port);
 T(!gta3xlwifi_lna_blocked(10001,index,&ip,6,port));T(gta3xlwifi_lna_blocked(10002,index,&ip,6,port));
 t.revision=2;
 for(int fail=1;fail<=5;fail++){alloc_fail_at=fail;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ENOMEM&&lna_current->revision==1&&rcu_graces==1);}alloc_fail_at=0;
 for(int fail=1;fail<=3;fail++){from_fail=fail;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EFAULT&&lna_current->revision==1&&rcu_graces==1);}from_fail=0;
 t.version=2;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.version=1;t.reserved=1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.reserved=0;
 t.network_count=1001;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.network_count=2;t.host_count=1001;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.host_count=1;
 t.network_entries=0;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.network_entries=(uintptr_t)n;
 n[1].prefix_bits=193;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[1].prefix_bits=192;n[1].allowed=2;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[1].allowed=1;
 for(unsigned i=0;i<3;i++){n[1].reserved[i]=1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[1].reserved[i]=0;}
 n[0].key[23]=1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[0].key[23]=0;
 struct gta3xlwifi_lna_entry saved=n[1];n[1]=n[0];T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[1]=saved;
 t.revision=0;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ESTALE);t.revision=3;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ESTALE);t.revision=1;n[0].allowed=1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ESTALE);n[0].allowed=0;
 struct gta3xlwifi_lna_entry outn[3],outh[2];memset(outn,0x5a,sizeof(outn));memset(outh,0x5a,sizeof(outh));
 q=tx(0,0,NULL,0,NULL);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==0&&q.revision==1&&q.network_count==2&&q.host_count==1);
 q=tx(0,3,outn,2,outh);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==-ESTALE&&outn[0].prefix_bits==0x5a5a5a5a);
 q=tx(1,1,outn,1,outh);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==-ENOSPC&&q.network_count==2&&outn[0].prefix_bits==0x5a5a5a5a);
 q=tx(1,3,outn,2,outh);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==0&&q.network_count==2&&q.host_count==1&&!memcmp(n,outn,sizeof(n))&&!memcmp(host,outh,sizeof(host)));
 for(int fail=1;fail<=3;fail++){to_fail=fail;q=tx(1,3,outn,2,outh);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==-EFAULT&&lna_current->revision==1);}to_fail=0;
 T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==0&&!gta3xlwifi_netpolicy_held());t.revision=2;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EBUSY&&lna_current->revision==1);q=tx(0,0,NULL,0,NULL);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==0&&!gta3xlwifi_netpolicy_held());T(io(GTA3XLWIFI_NETPOLICY_HOLD,NULL)==0);
 // Exhaustive actual A17 permission expression, literal vs per-user core UIDs.
 struct gta3xlwifi_lna_entry deny={.prefix_bits=0,.allowed=0};t=tx(2,1,&deny,0,NULL);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);reference_image(&deny,1,NULL,0);
 const u32 uids[]={0,1,1000,9999,10001,65534,100001,101000,110001,2147483647};
 for(unsigned u=0;u<sizeof(uids)/sizeof(uids[0]);u++)for(u32 mask=0;mask<128;mask++){
  struct gta3xlwifi_uid_permission_entry permission={uids[u],mask};struct gta3xlwifi_uid_permission_transfer ut={1,mask?1:0,uid_image?uid_image->revision+1:1,mask?(uintptr_t)&permission:0};assert(io(GTA3XLWIFI_UID_SET_IMAGE,&ut)==0);
  check_decision(uids[u],index,&ip,proto,port);
 }
 T(gta3xlwifi_lna_blocked(10001,index,NULL,proto,port));
 struct gta3xlwifi_uid_permission_transfer clear={1,0,uid_image->revision+1,0};assert(io(GTA3XLWIFI_UID_SET_IMAGE,&clear)==0);

 // Actual Java producer uses a64-bit UID/interface wildcard, not only192 hosts.
 struct gta3xlwifi_lna_entry wide[2]={{.prefix_bits=64,.allowed=1},{.prefix_bits=192,.allowed=0}};
 memcpy(wide[0].key,&uidval,4);memcpy(wide[0].key+4,&index,4);
 memcpy(wide[1].key,wide[0].key,24);memcpy(wide[1].key+8,&ip,16);
 t=tx(lna_current->revision+1,1,&deny,2,wide);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);reference_image(&deny,1,wide,2);
 T(gta3xlwifi_lna_blocked(uidval,index,&ip,proto,port));check_decision(uidval,index,&ip,proto,port);
 struct in6_addr other=ip;other.s6_addr[15]^=1;T(!gta3xlwifi_lna_blocked(uidval,index,&other,proto,port));check_decision(uidval,index,&other,proto,port);
 T(gta3xlwifi_lna_blocked(uidval,index+1,&other,proto,port));check_decision(uidval,index+1,&other,proto,port);
 T(gta3xlwifi_lna_blocked(uidval+1,index,&other,proto,port));check_decision(uidval+1,index,&other,proto,port);
 struct in6_addr mapped={0};mapped.s6_addr[10]=mapped.s6_addr[11]=255;mapped.s6_addr[12]=192;mapped.s6_addr[15]=1;T(!gta3xlwifi_lna_blocked(uidval,index,&mapped,proto,port));check_decision(uidval,index,&mapped,proto,port);
 wide[0].allowed=0;wide[1].allowed=1;t.revision=lna_current->revision+1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);
 T(!gta3xlwifi_lna_blocked(uidval,index,&ip,proto,port));T(gta3xlwifi_lna_blocked(uidval,index,&other,proto,port));check_decision(uidval,index,&ip,proto,port);check_decision(uidval,index,&other,proto,port);
 // Independent slow bit-loop oracle across compressed branch/ancestor/sibling paths.
 struct gta3xlwifi_lna_entry many[1000],hosts[1000];
 for(unsigned round=0;round<64;round++){
  u32 nc=round==0?1000:random32()%1001,hc=round==0?1000:random32()%1001;
  for(unsigned which=0;which<2;which++){
   struct gta3xlwifi_lna_entry*e=which?hosts:many;u32 count=which?hc:nc;
   for(u32 i=0;i<count;i++){memset(&e[i],0,sizeof(e[i]));e[i].prefix_bits=random32()%193;e[i].allowed=random32()&1;for(unsigned b=0;b<24;b++)e[i].key[b]=random32();lna_canonical(e[i].key,e[i].prefix_bits);}
   qsort(e,count,sizeof(*e),compare);u32 unique=0;for(u32 i=0;i<count;i++)if(!unique||compare(&e[unique-1],&e[i]))e[unique++]=e[i];if(which)hc=unique;else nc=unique;
  }
  t=tx(lna_current->revision+1,nc,nc?many:NULL,hc,hc?hosts:NULL);assert(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);reference_image(many,nc,hosts,hc);
  assert(lna_current->network.nodes_count<=2*nc&&lna_current->host.nodes_count<=2*hc);
  for(unsigned i=0;i<4096;i++){
   u8 key[24];for(unsigned b=0;b<24;b++)key[b]=random32();if(nc&&i%2==0){u32 e=random32()%nc;memcpy(key,many[e].key,24);for(u32 bit=many[e].prefix_bits;bit<192;bit++)if(random32()&1)key[bit/8]^=1U<<(7-bit%8);}
   u32 queryIndex;u16 queryProto;__be16 queryPort;memcpy(&queryIndex,key,4);memcpy(&ip,key+4,16);memcpy(&queryProto,key+20,2);memcpy(&queryPort,key+22,2);
   check_decision(uids[i%10],queryIndex,&ip,queryProto,queryPort);
   bool actual=false;const struct gta3xlwifi_lna_entry*expected=slow_lpm(many,nc,key);bool found=lna_lookup(&lna_current->network,key,&actual);assert(found==!!expected&&(!found||actual==!!expected->allowed));++comparisons;
   expected=slow_lpm(hosts,hc,key);found=lna_lookup(&lna_current->host,key,&actual);assert(found==!!expected&&(!found||actual==!!expected->allowed));++comparisons;
  }
 }
 // Every prefix boundary plus nested ancestor precedence, including0/192.
 for(u32 bits=0;bits<=192;bits++){
  memset(many,0,2*sizeof(*many));many[0].allowed=1;many[1].prefix_bits=bits;many[1].allowed=0;memset(many[1].key,0xaa,24);lna_canonical(many[1].key,bits);u32 count=bits?2:1;if(!bits)many[0].allowed=0;
  t=tx(lna_current->revision+1,count,many,0,NULL);assert(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);
  bool value=true;assert(lna_lookup(&lna_current->network,many[1].key,&value)&&!value);++comparisons;
 }
 lna_current->revision=UINT64_MAX;t=tx(UINT64_MAX,lna_current->network.count,lna_current->network.entries,0,NULL);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);t.revision=0;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EOVERFLOW);
 T(netpolicy_flush(&owner,NULL)==0&&gta3xlwifi_netpolicy_held()&&parent_pid.refs==0);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==-ENOTCONN);T(netpolicy_release(NULL,&owner)==0);
 lna_free(lna_current);lna_current=NULL;vfree(uid_image);uid_image=NULL;T(allocs==frees&&!publication_pending&&!rcu_depth);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
