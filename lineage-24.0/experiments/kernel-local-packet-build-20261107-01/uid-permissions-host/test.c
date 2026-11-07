
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

#include <linux/netfilter/gta3xlwifi_local_network.h>
static long gta3xlwifi_lna_ioctl(unsigned int c,unsigned long arg){(void)c;(void)arg;assert(!"UID-only regression entered LNA store");return -ENOTTY;}

static u32 gta3xlwifi_lna_packet_features(void){return 0;}

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
#define PERMISSION_BIT_NO_INTERNET (1 << 2)
static u32 oracle_uid,oracle_mask;
static u32 get_chunk_permissions(u32 uid){return uid==oracle_uid?oracle_mask:0;}
#define BPF_ALLOW 1
#define BPF_DISALLOW 0
static int oracle(u32 uid){return (get_chunk_permissions(uid) & PERMISSION_BIT_NO_INTERNET)
                   ? BPF_DISALLOW
                   : BPF_ALLOW;}


struct fake_proto{int(*init)(void*);};struct fake_sock{struct fake_proto*sk_prot;};
static unsigned release_count,init_calls;static int init_error;
static void sk_common_release(struct fake_sock*s){assert(s);++release_count;}
static int proto_init(void*s){assert(s);++init_calls;return init_error;}

static int tail0(struct fake_sock*sk,bool kern){int err=0;	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err) {
			sk_common_release(sk);
			goto out;
		}
	}
	if (!kern) {
		err = gta3xlwifi_uid_inet_create_check();
		if (err)
			sk_common_release(sk);
	}
out:
return err;}

static int tail1(struct fake_sock*sk,bool kern){int err=0;	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err) {
			sk_common_release(sk);
			goto out;
		}
	}
	if (!kern) {
		err = gta3xlwifi_uid_inet_create_check();
		if (err)
			sk_common_release(sk);
	}
out:
return err;}


static unsigned cases,comparisons;
#define T(x) do{if(!(x)){fprintf(stderr,"failed line %d: %s\n",__LINE__,#x);abort();}++cases;}while(0)
static struct file owner={1},other={2};
static long io(unsigned cmd,void*p){from_calls=to_calls=0;return netpolicy_ioctl(&owner,cmd,(unsigned long)p);}
static struct gta3xlwifi_uid_permission_transfer tx(u64 revision,u32 count,void*e){return (struct gta3xlwifi_uid_permission_transfer){1,count,revision,(uintptr_t)e};}
static u64 revision(void){return uid_image?uid_image->revision:0;}
static void unchanged(u64 rev,unsigned graces){assert(revision()==rev&&rcu_graces==graces&&gta3xlwifi_netpolicy_held());}
int main(void){
 T(sizeof(struct gta3xlwifi_uid_permission_transfer)==24&&offsetof(struct gta3xlwifi_uid_permission_transfer,entries)==16);
 T(sizeof(struct gta3xlwifi_uid_permission_entry)==8&&GTA3XLWIFI_UID_FEATURES==0x6754);
 T(_IOC_SIZE(GTA3XLWIFI_UID_SET_IMAGE)==24&&_IOC_NR(GTA3XLWIFI_UID_GET_IMAGE)==0x56);
 T(gta3xlwifi_uid_permissions(10001)==0&&gta3xlwifi_uid_permissions_features()==7);
 struct gta3xlwifi_uid_permission_entry e[]={{0,1},{10001,4},{110001,127},{2147483647,1}};
 struct gta3xlwifi_uid_permission_transfer t=tx(1,4,e);
 T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ENOTCONN);
 T(netpolicy_open(NULL,&owner)==0&&gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_UID_FEATURES,NULL)==15&&gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_UID_FEATURES,&t)==-EINVAL);
 T(io(GTA3XLWIFI_UID_SET_IMAGE,NULL)==-EFAULT);
 T(io(GTA3XLWIFI_UID_GET_IMAGE,NULL)==-EFAULT);
 T(io(0x6757,NULL)==-ENOTTY&&gta3xlwifi_netpolicy_held());
 T(netpolicy_image_ioctl(&owner,0x6757,0)==-ENOTTY);
 // All new operations enforce the same root + initial CAP_NET_ADMIN + file/TGID.
 for(unsigned i=0;i<3;i++){
  unsigned cmd=i==0?GTA3XLWIFI_UID_FEATURES:i==1?GTA3XLWIFI_UID_SET_IMAGE:GTA3XLWIFI_UID_GET_IMAGE;void*arg=i?&t:NULL;
  task.euid=1000;T(io(cmd,arg)==-EPERM);task.euid=0;
  task.admin=false;T(io(cmd,arg)==-EPERM);task.admin=true;
  task.tgid=&child_pid;T(io(cmd,arg)==-EPERM);task.tgid=&parent_pid;
  T(netpolicy_ioctl(&other,cmd,(unsigned long)arg)==-EPERM);
 }
 T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0&&revision()==1&&rcu_graces==1);
 for(u32 uid=0;uid<120000;uid++){u32 expected=uid==0?1:uid==10001?4:uid==110001?127:0;assert(gta3xlwifi_uid_permissions(uid)==expected);++comparisons;}
 T(gta3xlwifi_uid_permissions(2147483647)==1&&gta3xlwifi_uid_permissions(0xffffffff)==0);
 T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0&&rcu_graces==1); // idempotent, no replace
 unsigned grace=rcu_graces;u64 rev=revision();
 t.revision=2;alloc_fail=1;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ENOMEM);alloc_fail=0;unchanged(rev,grace);
 from_fail=1;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EFAULT);unchanged(rev,grace);
 from_fail=2;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EFAULT);from_fail=0;unchanged(rev,grace);
 t.version=2;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);t.version=1;
 t.count=65537;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);t.count=4;
 t.entries=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);t.entries=(uintptr_t)e;
 t.count=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);t.count=4;
 e[1].permissions=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);e[1].permissions=128;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);e[1].permissions=4;
 e[1].uid=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);e[1].uid=0xffffffff;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);e[1].uid=10001;
 t.revision=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ESTALE);t.revision=3;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ESTALE);
 t.revision=1;e[1].permissions=1;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ESTALE);e[1].permissions=4;unchanged(rev,grace);
 // GET metadata and coherent full image: stale/capacity/copy failures never write policy.
 struct gta3xlwifi_uid_permission_transfer q=tx(0,0,NULL);
 T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==0&&q.count==4&&q.revision==1&&gta3xlwifi_netpolicy_held());
 struct gta3xlwifi_uid_permission_entry out[8];memset(out,0x5a,sizeof(out));
 q=tx(0,8,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-ESTALE&&out[0].uid==0x5a5a5a5a);
 q=tx(2,8,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-ESTALE);
 q=tx(1,1,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-ENOSPC&&q.count==4&&out[0].uid==0x5a5a5a5a);
 q=tx(1,8,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==0&&q.count==4&&memcmp(e,out,sizeof(e))==0);
 for(int fail=1;fail<=2;fail++){q=tx(1,8,out);to_fail=fail;T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EFAULT);unchanged(rev,grace);}to_fail=0;
 q=tx(1,1,out);to_fail=1;T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EFAULT);to_fail=0;
 T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==0&&!gta3xlwifi_netpolicy_held());
 t.revision=2;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EBUSY&&revision()==1);
 q=tx(0,0,NULL);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==0&&!gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_UID_FEATURES,NULL)==15&&!gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_NETPOLICY_HOLD,NULL)==0&&gta3xlwifi_netpolicy_held());
 // Exhaustive bit patterns, core/app/multiuser/literal65534 and privileged controls.
 const u32 uids[]={0,1000,9999,10000,10001,65534,100001,110001,2147483647};
 for(unsigned u=0;u<sizeof(uids)/sizeof(uids[0]);u++)for(u32 mask=0;mask<128;mask++){
  struct gta3xlwifi_uid_permission_entry one={uids[u],mask};
  t=tx(revision()+1,mask?1:0,mask?&one:NULL);assert(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);
  oracle_uid=uids[u];oracle_mask=mask;task.uid=uids[u];
  for(int cap=0;cap<2;cap++)for(int held=0;held<2;held++){
   task.admin=cap;WRITE_ONCE(netpolicy_held,held);
   int expected=oracle(task.uid)==BPF_DISALLOW?-EPERM:held&&task.uid%100000>=10000&&!cap?-EAGAIN:0;
   assert(gta3xlwifi_uid_inet_create_check()==expected);++comparisons;
  }
  task.admin=true;WRITE_ONCE(netpolicy_held,true);
 }
 task.uid=0;
 // Max sized sparse table tests full copy, last-element search and bounded allocation.
 struct gta3xlwifi_uid_permission_entry*many=calloc(65536,sizeof(*many));assert(many);
 for(u32 i=0;i<65536;i++)many[i]=(struct gta3xlwifi_uid_permission_entry){i*2,1};
 t=tx(revision()+1,65536,many);T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);free(many);
 T(gta3xlwifi_uid_permissions(131070)==1&&gta3xlwifi_uid_permissions(131069)==0);
 // Empty replacement is explicit and revisioned, not absent/uninitialized.
 t=tx(revision()+1,0,NULL);T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);
 q=tx(0,0,NULL);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==0&&q.count==0&&q.revision==revision());
 q=tx(0,0,NULL);q.version=0;T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EINVAL);
 q=tx(0,65537,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EINVAL);
 q=tx(0,1,NULL);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EINVAL);
 T(gta3xlwifi_uid_permissions_ioctl(0x6757,0)==-ENOTTY);
 // Overflow never wraps; identical final revision remains idempotent.
 uid_image->revision=UINT64_MAX;t=tx(UINT64_MAX,0,NULL);T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);
 t.revision=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EOVERFLOW);uid_image->revision=1;
 struct gta3xlwifi_uid_permission_entry denied={10001,4};t=tx(2,1,&denied);
 T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);
 // Both actual inet tails: init error once, denial once, kern exclusion, success.
 struct fake_proto proto={proto_init};struct fake_sock sk={&proto};
 for(unsigned family=0;family<2;family++){
  int(*tail)(struct fake_sock*,bool)=family?tail1:tail0;
  task.uid=10002;task.admin=false;WRITE_ONCE(netpolicy_held,true);release_count=init_calls=0;init_error=-EIO;
  T(tail(&sk,false)==-EIO&&release_count==1&&init_calls==1);
  init_error=0;release_count=0;T(tail(&sk,false)==-EAGAIN&&release_count==1);
  release_count=0;T(tail(&sk,true)==0&&release_count==0);
  task.uid=10001;WRITE_ONCE(netpolicy_held,false);T(tail(&sk,false)==-EPERM&&release_count==1);
  task.uid=0;release_count=0;T(tail(&sk,false)==0&&release_count==0);
  proto.init=NULL;T(tail(&sk,false)==0&&release_count==0);proto.init=proto_init;
 }
 task.uid=0;task.admin=true;T(netpolicy_flush(&owner,NULL)==0&&gta3xlwifi_netpolicy_held()&&parent_pid.refs==0);
 T(io(GTA3XLWIFI_UID_FEATURES,NULL)==-ENOTCONN);T(netpolicy_release(NULL,&owner)==0);
 vfree(uid_image);uid_image=NULL;T(allocs==frees&&!rcu_depth&&!publication_pending);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
