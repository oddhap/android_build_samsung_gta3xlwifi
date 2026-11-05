/* Task/socket/skb metadata fixtures. All permission/SID/lookup bodies are real. */
#define LSM_AUDIT_DATA_NET 7
#define LSM_AUDIT_DATA_NLMSGTYPE 8
struct nlmsghdr {u32 nlmsg_len;u16 nlmsg_type,nlmsg_flags;u32 nlmsg_seq,nlmsg_pid;};
#define NLMSG_ALIGN(x) (((x)+NLMSG_ALIGNTO-1)&~(NLMSG_ALIGNTO-1))
#define nlmsg_total_size(x) (NLMSG_ALIGN(NLMSG_HDRLEN+(x)))
#define BUILD_BUG_ON(x) do{_Static_assert(!(x),"kernel bound");}while(0)
/* ACTUAL_SOCKET_SECURITY_STRUCT */
struct sock {struct sk_security_struct *sk_security;u16 sk_protocol;};
struct sk_buff {unsigned len;unsigned char *data;};
struct task_struct {char comm[8];};
static struct task_struct actor={"fixture"};
#define current (&actor)
static u32 actor_sid;
static u32 task_sid(struct task_struct *t){assert(t==current);return actor_sid;}
static u32 current_sid(void){return actor_sid;}
static unsigned task_pid_nr(struct task_struct *t){assert(t==current);return 100;}
int selinux_android_netlink_route,selinux_policycap_alwaysnetwork;
