/* Stateful single-entry host cache/RCU/audit backends, not native cache execution. */
#define noinline __attribute__((noinline))
struct list_head {struct list_head *next,*prev;};
struct hlist_node {void *next,*pprev;};struct rcu_head {void *next,*func;};
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,__typeof__(*p),m);&(p)->m!=(h);p=container_of((p)->m.next,__typeof__(*p),m))
#define INIT_LIST_HEAD(h) do{(h)->next=(h);(h)->prev=(h);}while(0)
static unsigned rcu_depth,cache_mode,cache_valid,cache_adds,audit_calls;
static int selinux_enforcing=1;
static void rcu_read_lock(void){assert(!rcu_depth);rcu_depth++;}
static void rcu_read_unlock(void){assert(rcu_depth==1);rcu_depth--;}
struct sock;
struct lsm_network_audit {struct sock *sk;};
struct common_audit_data {int type;union {struct lsm_network_audit *net;u16 nlmsg_type;} u;};
/* ACTUAL_AVC_STRUCTS */
static struct avc_node cache_node;
static struct avc_xperms_node cache_xp;
static struct avc_xperms_decision_node cached[2];
static struct extended_perms_data cached_bits[2][3];
static unsigned cached_count;
static void reset_cache(unsigned mode){memset(&cache_node,0,sizeof(cache_node));memset(&cache_xp,0,sizeof(cache_xp));INIT_LIST_HEAD(&cache_xp.xpd_head);cache_mode=mode;cache_valid=cache_adds=cached_count=0;}
static struct avc_node *avc_lookup(u32 s,u32 t,u16 c){assert(rcu_depth==1);if(!cache_valid||!cache_mode)return NULL;assert(cache_node.ae.ssid==s&&cache_node.ae.tsid==t&&cache_node.ae.tclass==c);return &cache_node;}
static struct avc_node *avc_insert(u32 s,u32 t,u16 c,struct av_decision *d,struct avc_xperms_node *xp){assert(rcu_depth==1);if(!cache_mode)return NULL;cache_node.ae.ssid=s;cache_node.ae.tsid=t;cache_node.ae.tclass=c;cache_node.ae.avd=*d;cache_xp.xp=xp->xp;INIT_LIST_HEAD(&cache_xp.xpd_head);cache_node.ae.xp_node=&cache_xp;cache_valid=1;return &cache_node;}
static void add_xpd(struct extended_perms_decision *d){assert(cached_count<2);unsigned i=cached_count++;cached[i].xpd=*d;cached_bits[i][0]=*d->allowed;cached_bits[i][1]=*d->auditallow;cached_bits[i][2]=*d->dontaudit;cached[i].xpd.allowed=&cached_bits[i][0];cached[i].xpd.auditallow=&cached_bits[i][1];cached[i].xpd.dontaudit=&cached_bits[i][2];struct list_head *h=&cache_xp.xpd_head,*n=&cached[i].xpd_list;n->next=h;n->prev=h->prev;h->prev->next=n;h->prev=n;}
static int avc_update_node(u32 event,u32 perms,u8 driver,u8 base,u8 command,u32 s,u32 t,u16 c,u32 seq,struct extended_perms_decision *d,u32 flags){assert(rcu_depth==1 && event==AVC_CALLBACK_ADD_XPERMS && d && flags==0 && (seq==19||seq==latest_granting));(void)perms;(void)driver;(void)base;(void)command;(void)s;(void)t;(void)c;if(cache_mode==2){assert(cache_valid);add_xpd(d);cache_adds++;}return 0;}
static int slow_avc_audit(u32 s,u32 t,u16 c,u32 requested,u32 audited,u32 denied,int result,struct common_audit_data *ad,unsigned flags){assert(!rcu_depth && !lock_depth && audited);(void)s;(void)t;(void)c;(void)requested;(void)denied;(void)result;(void)ad;(void)flags;audit_calls++;return 0;}
