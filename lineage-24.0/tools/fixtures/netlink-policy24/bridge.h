#ifndef NETLINK_POLICY_HOST_BRIDGE
#define NETLINK_POLICY_HOST_BRIDGE
/* Sequential host locking/audit fixtures, no kernel concurrency model. */
#include <host.h>
#define pr_warn_once pr_warn
#define pr_warn_ratelimited pr_warn
#define printk_ratelimit() 1
#define spin_lock_init(p) (*(p)=0)
#define spin_lock_irqsave(p,f) do{assert(!*(p));*(p)=1;(f)=0;}while(0)
#define spin_unlock_irqrestore(p,f) do{assert(*(p));*(p)=0;(void)(f);}while(0)
#define wmb() ((void)0)
#define rmb() ((void)0)
#define smp_rmb() ((void)0)
#define smp_wmb() ((void)0)
#define READ_ONCE(v) (v)
#define WRITE_ONCE(v,x) ((v)=(x))
static unsigned lock_depth;
void host_unlock_hook(void);
#define read_lock(p) do{(void)(p);assert(!lock_depth);lock_depth++;}while(0)
#define read_unlock(p) do{(void)(p);assert(lock_depth==1);lock_depth--;host_unlock_hook();}while(0)

#endif
