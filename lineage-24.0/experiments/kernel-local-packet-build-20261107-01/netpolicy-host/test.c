
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <linux/netfilter/gta3xlwifi_netpolicy.h>
#define CONFIG_COMPAT 1
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define MISC_DYNAMIC_MINOR 255
#define CAP_NET_ADMIN 12
#define GLOBAL_ROOT_UID 0
#define NFPROTO_UNSPEC 0
#define NF_INET_LOCAL_IN 1
#define NF_INET_FORWARD 2
#define NF_INET_LOCAL_OUT 3
struct inode{int unused;};struct file{int identity;};typedef void* fl_owner_t;
struct pid{unsigned identity;int refs;};
struct task_struct{unsigned uid;bool admin;struct pid* tgid;};
static __thread struct task_struct* current;
static int init_user_ns;
static unsigned current_euid(void){return current->uid;}
static bool uid_eq(unsigned a,unsigned b){return a==b;}
static bool ns_capable(const void* ns,int capability){assert(ns==&init_user_ns&&capability==CAP_NET_ADMIN);return current->admin;}
static struct pid* task_tgid(struct task_struct* task){return task->tgid;}
static struct pid* get_pid(struct pid* p){assert(p);++p->refs;return p;}
static void put_pid(struct pid* p){assert(p&&p->refs>0);--p->refs;}
#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER
static void checked_mutex_lock(pthread_mutex_t* lock);
#define mutex_lock(n) checked_mutex_lock(n)
#define mutex_unlock(n) assert(pthread_mutex_unlock(n)==0)
#define WRITE_ONCE(p,v) __atomic_store_n(&(p),(v),__ATOMIC_RELAXED)
#define READ_ONCE(p) __atomic_load_n(&(p),__ATOMIC_RELAXED)
#define smp_store_release(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
struct sk_buff{int unused;};struct xt_action_param{int family;};
struct xt_mtchk_param{const void* matchinfo;};
struct file_operations{void*owner;int(*open)(struct inode*,struct file*);int(*flush)(struct file*,fl_owner_t);int(*release)(struct inode*,struct file*);long(*unlocked_ioctl)(struct file*,unsigned int,unsigned long);long(*compat_ioctl)(struct file*,unsigned int,unsigned long);};
struct miscdevice{int minor;const char*name;const struct file_operations*fops;unsigned mode;};
struct xt_match{const char*name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void*me;};
static unsigned syncs;
static bool pause_grace,reached_grace,allow_grace,waiter_blocked;
static __thread bool is_closer;
static pthread_mutex_t coordination=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition=PTHREAD_COND_INITIALIZER;

#include <linux/netfilter/gta3xlwifi_uid_permissions.h>
#define EXPORT_SYMBOL_GPL(x)
static long netpolicy_image_ioctl(struct file*f,unsigned int c,unsigned long a){(void)f;(void)c;(void)a;assert(!"legacy test entered image dispatch");return -ENOTTY;}

#include <linux/netfilter/gta3xlwifi_local_network.h>
static DEFINE_MUTEX(netpolicy_lock);
static struct file *netpolicy_owner_file;
static struct pid *netpolicy_owner_pid;
static bool netpolicy_held = true;

bool gta3xlwifi_netpolicy_held(void)
{
	return smp_load_acquire(&netpolicy_held);
}
EXPORT_SYMBOL_GPL(gta3xlwifi_netpolicy_held);



static void checked_mutex_lock(pthread_mutex_t* lock){
 if(is_closer){assert(pthread_mutex_trylock(lock)==EBUSY);pthread_mutex_lock(&coordination);waiter_blocked=true;pthread_cond_broadcast(&condition);pthread_mutex_unlock(&coordination);}
 assert(pthread_mutex_lock(lock)==0);
}
static void synchronize_net(void){
 assert(READ_ONCE(netpolicy_held));++syncs;
 assert(pthread_mutex_lock(&coordination)==0);
 if(pause_grace){reached_grace=true;pthread_cond_broadcast(&condition);while(!allow_grace)pthread_cond_wait(&condition,&coordination);}
 pthread_mutex_unlock(&coordination);
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
static bool netpolicy_match(const struct sk_buff *skb,
			    struct xt_action_param *par)
{
	return smp_load_acquire(&netpolicy_held);
}
static int netpolicy_check(const struct xt_mtchk_param *par)
{
	const struct gta3xlwifi_netpolicy_match *info = par->matchinfo;
	unsigned int i;

	for (i = 0; i < sizeof(info->reserved); i++)
		if (info->reserved[i])
			return -EINVAL;
	return 0;
}static const struct file_operations netpolicy_fops = {
	.owner = THIS_MODULE,
	.open = netpolicy_open,
	.flush = netpolicy_flush,
	.release = netpolicy_release,
	.unlocked_ioctl = netpolicy_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = netpolicy_ioctl,
#endif
};

static struct miscdevice netpolicy_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "gta3xlwifi_netpolicy",
	.fops = &netpolicy_fops,
	.mode = 0400,
};

static struct xt_match netpolicy_match_reg __read_mostly = {
	.name = GTA3XLWIFI_NETPOLICY_MATCH,
	.revision = 0,
	.family = NFPROTO_UNSPEC,
	.hooks = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
		 (1 << NF_INET_LOCAL_OUT),
	.match = netpolicy_match,
	.checkentry = netpolicy_check,
	.matchsize = sizeof(struct gta3xlwifi_netpolicy_match),
	.me = THIS_MODULE,
};


static int register_error,misc_error;
static unsigned registers,unregisters,misc_calls;
static int xt_register_match(struct xt_match* m){assert(m==&netpolicy_match_reg);++registers;return register_error;}
static void xt_unregister_match(struct xt_match* m){assert(m==&netpolicy_match_reg);++unregisters;}
static int misc_register(struct miscdevice* m){assert(m==&netpolicy_device);++misc_calls;return misc_error;}
static int __init gta3xlwifi_netpolicy_init(void)
{
	int ret;

	ret = xt_register_match(&netpolicy_match_reg);
	if (ret)
		return ret;
	ret = misc_register(&netpolicy_device);
	if (ret)
		xt_unregister_match(&netpolicy_match_reg);
	return ret;
}
static struct pid parent_pid={42,0},child_pid={43,0};
static struct task_struct parent={0,true,&parent_pid},child={0,true,&child_pid};
static struct file owner={1},foreign={2};
static long open_result;
static void* releasing(void* arg){(void)arg;current=&parent;open_result=netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0);return NULL;}
static void* closing(void* arg){(void)arg;current=&parent;is_closer=true;assert(netpolicy_flush(&owner,NULL)==0);return NULL;}
int main(void){unsigned checks=0;current=&parent;
#define C(x) do{assert(x);++checks;}while(0)
 C(GTA3XLWIFI_NETPOLICY_ABI==0x6750&&GTA3XLWIFI_NETPOLICY_HOLD==0x6751&&GTA3XLWIFI_NETPOLICY_RELEASE==0x6752&&GTA3XLWIFI_NETPOLICY_STATE==0x6753);
 C(sizeof(struct gta3xlwifi_netpolicy_match)==4);
 C(netpolicy_match(NULL,NULL));
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_STATE,0)==-ENOTCONN);
 parent.uid=1000;C(netpolicy_open(NULL,&owner)==-EPERM);parent.uid=0;parent.admin=false;C(netpolicy_open(NULL,&owner)==-EPERM);parent.admin=true;parent.tgid=NULL;C(netpolicy_open(NULL,&owner)==-EPERM);parent.tgid=&parent_pid;
 C(netpolicy_open(NULL,&owner)==0&&parent_pid.refs==1&&syncs==1);
 C(netpolicy_open(NULL,&foreign)==-EBUSY&&parent_pid.refs==1);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_ABI,0)==1);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_STATE,0)==1);
 C(netpolicy_ioctl(&owner,0x6757,0)==-ENOTTY);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,1)==-EINVAL&&netpolicy_match(NULL,NULL));
 C(netpolicy_ioctl(&foreign,GTA3XLWIFI_NETPOLICY_RELEASE,0)==-EPERM);
 current=&child;C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==-EPERM);current=&parent;
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0&&!netpolicy_match(NULL,NULL)&&syncs==2);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0&&syncs==2);
 current=&child;C(netpolicy_flush(&owner,NULL)==0&&!netpolicy_match(NULL,NULL)&&parent_pid.refs==1);current=&parent;
 parent.admin=false;C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==-EPERM);parent.admin=true;
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0&&netpolicy_match(NULL,NULL)&&syncs==3);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0&&!netpolicy_match(NULL,NULL));
 parent.uid=1000;parent.admin=false;C(netpolicy_flush(&owner,NULL)==0&&netpolicy_match(NULL,NULL)&&parent_pid.refs==0);parent.uid=0;parent.admin=true;
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_STATE,0)==-ENOTCONN);
 C(netpolicy_open(NULL,&foreign)==0&&parent_pid.refs==1);
 C(netpolicy_release(NULL,&owner)==0&&netpolicy_owner_file==&foreign&&parent_pid.refs==1);
 C(netpolicy_ioctl(&foreign,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0&&!netpolicy_match(NULL,NULL));
 current=&child;C(netpolicy_release(NULL,&foreign)==0&&netpolicy_match(NULL,NULL)&&parent_pid.refs==0);current=&parent;
 struct gta3xlwifi_netpolicy_match info={{0}};struct xt_mtchk_param param={&info};C(netpolicy_check(&param)==0);
 for(unsigned i=0;i<4;i++){info.reserved[i]=1;C(netpolicy_check(&param)==-EINVAL);info.reserved[i]=0;}
 C(netpolicy_fops.flush==netpolicy_flush&&netpolicy_fops.compat_ioctl==netpolicy_ioctl);
 C(netpolicy_device.mode==0400);
 C(netpolicy_match_reg.family==NFPROTO_UNSPEC&&netpolicy_match_reg.hooks==((1<<NF_INET_LOCAL_IN)|(1<<NF_INET_FORWARD)|(1<<NF_INET_LOCAL_OUT))&&netpolicy_match_reg.matchsize==4);
 register_error=-ENOMEM;C(gta3xlwifi_netpolicy_init()==-ENOMEM&&registers==1&&misc_calls==0&&unregisters==0);
 register_error=0;misc_error=-EBUSY;C(gta3xlwifi_netpolicy_init()==-EBUSY&&registers==2&&misc_calls==1&&unregisters==1);
 misc_error=0;C(gta3xlwifi_netpolicy_init()==0&&registers==3&&misc_calls==2&&unregisters==1);
 C(netpolicy_open(NULL,&owner)==0);pause_grace=true;reached_grace=false;allow_grace=false;
 pthread_t a,b;C(pthread_create(&a,NULL,releasing,NULL)==0);
 pthread_mutex_lock(&coordination);while(!reached_grace)pthread_cond_wait(&condition,&coordination);C(netpolicy_match(NULL,NULL));pthread_mutex_unlock(&coordination);
 C(pthread_create(&b,NULL,closing,NULL)==0);
 pthread_mutex_lock(&coordination);while(!waiter_blocked)pthread_cond_wait(&condition,&coordination);allow_grace=true;pthread_cond_broadcast(&condition);pthread_mutex_unlock(&coordination);
 C(pthread_join(a,NULL)==0&&pthread_join(b,NULL)==0&&open_result==0&&netpolicy_match(NULL,NULL)&&parent_pid.refs==0);
 C(netpolicy_owner_file==NULL&&netpolicy_owner_pid==NULL);
 printf("passed_cases=%u\n",checks);
}
