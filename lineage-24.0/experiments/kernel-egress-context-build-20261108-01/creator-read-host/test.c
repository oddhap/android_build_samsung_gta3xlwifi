
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "tcp_states.h"
#define AF_INET 2
#define AF_INET6 10
typedef uint32_t u32;
typedef uint64_t u64;typedef uint32_t kuid_t;typedef uint32_t kgid_t;
struct user_namespace{int id;};static struct user_namespace init_user_ns={0};
struct task_struct{int unused;};static struct task_struct task;static struct task_struct* current=&task;
static uint32_t real_uid,real_gid;
static uint32_t current_uid(void){return real_uid;}
static void current_uid_gid(kuid_t* uid,kgid_t* gid){*uid=real_uid;*gid=real_gid;}
static uint32_t from_kuid(const struct user_namespace* ns,kuid_t uid){assert(ns==&init_user_ns);return uid;}
static uint32_t from_kgid(const struct user_namespace* ns,kgid_t gid){assert(ns==&init_user_ns);return gid;}
struct sock{uint32_t sk_uid,sk_gta_creator_uid;bool sk_gta_creator_valid;unsigned sk_family,sk_state;};
static inline bool sk_fullsock(const struct sock *sk)
{
	return (1 << sk->sk_state) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
}
void gta3xlwifi_socket_creator_init(struct sock *sk, bool kernel_socket)
{
	sk->sk_gta_creator_uid = 0;
	sk->sk_gta_creator_valid = false;
	if (!kernel_socket) {
		sk->sk_gta_creator_uid = from_kuid(&init_user_ns, current_uid());
		sk->sk_gta_creator_valid = true;
	}
}
static void gta3xlwifi_socket_creator_clone_reset(struct sock *sk)
{
	sk->sk_gta_creator_uid = 0;
	sk->sk_gta_creator_valid = false;
}
bool gta3xlwifi_socket_creator_uid(const struct sock *sk, u32 *uid)
{
	if (!sk || !uid || !sk_fullsock(sk))
		return false;
	if ((sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    !sk->sk_gta_creator_valid)
		return false;
	*uid = sk->sk_gta_creator_uid;
	return true;
}
static u64 reference_uid_gid(void)
{
	struct task_struct *task = current;
	kuid_t uid;
	kgid_t gid;

	if (!task)
		return -EINVAL;

	current_uid_gid(&uid, &gid);
	return (u64) from_kgid(&init_user_ns, gid) << 32 |
		from_kuid(&init_user_ns, uid);
}
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
int main(void){
 const uint32_t uids[]={0,1,9999,10000,10001,65534,100001,110001,0x7fffffff,0xffffffff};
 const uint32_t gids[]={0,1000,0xffffffff},inodes[]={0,10001,20001,0xffffffff};
 for(unsigned kernel=0;kernel<2;kernel++)for(unsigned u=0;u<10;u++)for(unsigned g=0;g<3;g++)for(unsigned i=0;i<4;i++){
  real_uid=uids[u];real_gid=gids[g];struct sock sk={.sk_uid=inodes[i],.sk_gta_creator_uid=123,.sk_gta_creator_valid=true,.sk_family=AF_INET,.sk_state=TCP_LISTEN};uint32_t expected=kernel?0:(uint32_t)reference_uid_gid();
  gta3xlwifi_socket_creator_init(&sk,kernel);assert(sk.sk_uid==inodes[i]&&sk.sk_gta_creator_uid==expected&&sk.sk_gta_creator_valid==!kernel);++comparisons;
  // Model current UID, inode ownership/graft and FD recipient changes. None is
  // an initialization hook, so the captured identity remains immutable.
  sk.sk_uid=54321;real_uid=12345;assert(sk.sk_gta_creator_uid==expected&&sk.sk_gta_creator_valid==!kernel);++comparisons;
  struct sock clone;memcpy(&clone,&sk,sizeof(clone));gta3xlwifi_socket_creator_clone_reset(&clone);
  assert(!clone.sk_gta_creator_valid&&clone.sk_gta_creator_uid==0&&clone.sk_uid==54321);++comparisons;
  assert(sk.sk_gta_creator_uid==expected&&sk.sk_gta_creator_valid==!kernel);++comparisons;
 }
 struct sock sk={.sk_uid=777,.sk_gta_creator_valid=true,.sk_family=AF_INET,.sk_state=TCP_ESTABLISHED};gta3xlwifi_socket_creator_clone_reset(&sk);T(!sk.sk_gta_creator_valid&&sk.sk_uid==777);gta3xlwifi_socket_creator_clone_reset(&sk);T(!sk.sk_gta_creator_valid&&sk.sk_uid==777);
 uint32_t out=777;
 T(!gta3xlwifi_socket_creator_uid(NULL,&out)&&out==777);
 T(!gta3xlwifi_socket_creator_uid(&sk,NULL));
 T(!gta3xlwifi_socket_creator_uid(&sk,&out)&&out==777);
 for(unsigned family=0;family<2;family++)for(unsigned state=1;state<TCP_MAX_STATES;state++){
  sk.sk_family=family?AF_INET6:AF_INET;sk.sk_state=state;sk.sk_gta_creator_valid=true;sk.sk_gta_creator_uid=65534;out=777;
  bool full=state!=TCP_TIME_WAIT&&state!=TCP_NEW_SYN_RECV;
  T(gta3xlwifi_socket_creator_uid(&sk,&out)==full&&out==(full?65534:777));
 }
 sk.sk_state=TCP_ESTABLISHED;sk.sk_family=AF_INET;sk.sk_gta_creator_valid=true;
 for(unsigned u=0;u<10;u++){sk.sk_gta_creator_uid=uids[u];out=777;T(gta3xlwifi_socket_creator_uid(&sk,&out)&&out==uids[u]);}
 sk.sk_family=1;out=777;T(!gta3xlwifi_socket_creator_uid(&sk,&out)&&out==777);
 sk.sk_family=0;T(!gta3xlwifi_socket_creator_uid(&sk,&out)&&out==777);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
