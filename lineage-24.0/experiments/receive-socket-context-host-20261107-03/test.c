
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
static struct pid parent_pid;static struct task task={0,0,true,&parent_pid};
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
	    cmd != GTA3XLWIFI_LNA_GET_IMAGE)
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
		      gta3xlwifi_lna_packet_features();
	else if ((cmd == GTA3XLWIFI_UID_SET_IMAGE || cmd == GTA3XLWIFI_LNA_SET_IMAGE) &&
	         !READ_ONCE(netpolicy_held))
		ret = -EBUSY;
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
	    cmd == GTA3XLWIFI_LNA_GET_IMAGE)
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


static unsigned cases;
#define T(x) do{if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}++cases;}while(0)
static struct file owner={1};
static long io(unsigned cmd,void*arg){from_calls=to_calls=alloc_attempt=0;return netpolicy_ioctl(&owner,cmd,(unsigned long)arg);}







#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <net/gta3xlwifi_packet.h>
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3
struct net{const void*user_ns;};struct sock{u32 uid;bool full;struct net*net;};
struct net_device{unsigned ifindex;};struct dst_entry{struct net_device*dev;};
struct sk_buff{u8 data[128];int length,network;u16 protocol;struct sock*sk;struct dst_entry*dst;};
struct xt_action_param{unsigned hooknum;const struct net_device*in;};
static uid_t overflowuid=65534;
static struct sock*skb_to_full_sk(const struct sk_buff*s){return s->sk&&s->sk->full?s->sk:NULL;}
static bool sk_fullsock(const struct sock*s){return s->full;}
static struct net*sock_net(struct sock*s){return s->net;}
static u32 sock_net_uid(struct net*n,struct sock*s){assert(s->net==n);return s->uid;}
static u32 from_kuid_munged(const void*n,u32 uid){assert(n==&init_user_ns);return uid;}
static struct dst_entry*skb_dst(const struct sk_buff*s){return s->dst;}
static int skb_network_offset(const struct sk_buff*s){return s->network;}
static int skb_copy_bits(const struct sk_buff*s,int off,void*out,int n){if(off<0||off+n>s->length)return -EFAULT;memcpy(out,s->data+off,n);return 0;}
static bool gta3xlwifi_packet_read(const struct sk_buff *skb, unsigned int offset,
                                  void *output, unsigned int length)
{
    if (skb_copy_bits(skb, skb_network_offset(skb) + offset, output, length)) {
        memset(output, 0, length);
        return false;
    }
    return true;
}
bool gta3xlwifi_parse_packet(const struct sk_buff *skb, struct gta3xlwifi_packet *packet)
{
    u8 protocol = 0, l4_offset = 0;
    struct { u8 protocol, length; } extension;
    if (!packet)
        return false;
    memset(packet, 0, sizeof(*packet));
    if (!skb)
        return false;
    if (skb->protocol == htons(ETH_P_IP)) {
        packet->ip_version = 4;
        packet->saddr.s6_addr32[2] = htonl(0xffff);
        gta3xlwifi_packet_read(skb, offsetof(struct iphdr, saddr),
                               &packet->saddr.s6_addr32[3], 4);
        packet->daddr.s6_addr32[2] = htonl(0xffff);
        gta3xlwifi_packet_read(skb, offsetof(struct iphdr, daddr),
                               &packet->daddr.s6_addr32[3], 4);
        gta3xlwifi_packet_read(skb, offsetof(struct iphdr, protocol), &protocol, 1);
        gta3xlwifi_packet_read(skb, 0, &l4_offset, 1);
        if (l4_offset < 0x45 || l4_offset > 0x4f)
            return false;
        l4_offset = (l4_offset & 0x0f) * 4;
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        packet->ip_version = 6;
        gta3xlwifi_packet_read(skb, offsetof(struct ipv6hdr, saddr), &packet->saddr, 16);
        gta3xlwifi_packet_read(skb, offsetof(struct ipv6hdr, daddr), &packet->daddr, 16);
        gta3xlwifi_packet_read(skb, offsetof(struct ipv6hdr, nexthdr), &protocol, 1);
        l4_offset = sizeof(struct ipv6hdr);
        if (protocol == IPPROTO_HOPOPTS || protocol == IPPROTO_DSTOPTS) {
            if (gta3xlwifi_packet_read(skb, l4_offset, &extension, sizeof(extension))) {
                protocol = extension.protocol;
                l4_offset += (extension.length + 1) * 8; /* A17 u8 wrapping. */
            }
        }
    } else {
        return false;
    }
    packet->ip_proto = protocol;
    switch (protocol) {
    case IPPROTO_TCP:
        gta3xlwifi_packet_read(skb, l4_offset + 13, &packet->tcp_flags, 1);
        /* fall through */
    case IPPROTO_DCCP:
    case IPPROTO_UDP:
    case IPPROTO_UDPLITE:
    case IPPROTO_SCTP:
        gta3xlwifi_packet_read(skb, l4_offset, &packet->sport, 2);
        gta3xlwifi_packet_read(skb, l4_offset + 2, &packet->dport, 2);
        break;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        gta3xlwifi_packet_read(skb, l4_offset, (char *)&packet->sport + 1, 1);
        gta3xlwifi_packet_read(skb, l4_offset + 1, (char *)&packet->dport + 1, 1);
        break;
    }
    return true;
}
static uid_t gta3xlwifi_raw_socket_uid(const struct sk_buff *skb)
{
	struct sock *sk = skb_to_full_sk(skb);
	struct net *net;

	if (!sk || !sk_fullsock(sk))
		return overflowuid;
	net = sock_net(sk);
	return from_kuid_munged(net->user_ns, sock_net_uid(net, sk));
}
static bool gta3xlwifi_lna_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    struct gta3xlwifi_packet packet;
    const struct net_device *device;
    u32 uid, if_index;
    bool output;
    if (!skb || !par || (par->hooknum != NF_INET_LOCAL_IN &&
                        par->hooknum != NF_INET_LOCAL_OUT))
        return false;
    if (!gta3xlwifi_parse_packet(skb, &packet))
        return false;
    output = par->hooknum == NF_INET_LOCAL_OUT;
    if (output) {
        const struct dst_entry *route = skb_dst(skb);
        device = route ? route->dev : NULL;
    } else {
        device = par->in;
    }
    if_index = device ? device->ifindex : 0;
    uid = gta3xlwifi_raw_socket_uid(skb);
    if (uid == 65534)
        uid = 0; /* Exact bpf_traffic_account normalization, NOT receiver UID. */
    return gta3xlwifi_lna_blocked(uid, if_index, output ? &packet.daddr : &packet.saddr,
                                  packet.ip_proto, output ? packet.dport : packet.sport);
}
int main(void){
 struct gta3xlwifi_lna_entry deny={.prefix_bits=0,.allowed=0};
 struct gta3xlwifi_lna_transfer t={1,1,0,0,1,(uintptr_t)&deny,0};
 T(netpolicy_open(NULL,&owner)==0);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);
 onetwork=&deny;oncount=1;ohost=NULL;ohcount=0;
 struct net net={&init_user_ns};struct sock receiver={10001,true,&net};
 struct sk_buff skb={.length=128,.protocol=htons(ETH_P_IP)};skb.data[0]=0x45;skb.data[9]=17;
 struct net_device input={17};struct xt_action_param par={1,&input};
 struct in6_addr remote={0};T(oracle_blocked(receiver.uid,17,&remote,17,0));
 T(!gta3xlwifi_lna_mt(&skb,&par)); // Unassociated raw UID65534 normalizes to root.
 struct sock*saved=skb.sk;skb.sk=&receiver; // Explicit fixture of modern wrapper binding.
 T(gta3xlwifi_lna_mt(&skb,&par));skb.sk=saved;T(skb.sk==NULL);
 T(netpolicy_flush(&owner,NULL)==0);T(netpolicy_release(NULL,&owner)==0);lna_free(lna_current);lna_current=NULL;
 T(allocs==frees);printf("passed_cases=%u context_gap_reproduced=1\n",cases);
}
