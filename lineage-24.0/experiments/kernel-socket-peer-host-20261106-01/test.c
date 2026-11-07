
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "tcp_states.h"
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define CONFIG_INET 1
#define CONFIG_IPV6 1
#define IS_ENABLED(x) (x)
#include <net/gta3xlwifi_socket_peer.h>
struct net{unsigned id;};static struct net fixture_net={123};
struct inet_hashinfo{int unused;};static struct inet_hashinfo tcp_hashinfo;
struct sock{unsigned sk_state,sk_family;u32 sk_gta_creator_uid;bool sk_gta_creator_valid;};
struct request_sock{struct sock* rsk_listener;};static struct request_sock request;
static struct sock original,listener;static struct sock* returned;
static unsigned references,lookups,puts,gets,expected_kind;
static int expected_ifindex;static struct gta3xlwifi_socket_peer_tuple expected_tuple;
static struct request_sock* inet_reqsk(struct sock* sk){assert(references==1&&sk==returned&&sk->sk_state==TCP_NEW_SYN_RECV);return &request;}
static inline bool sk_fullsock(const struct sock *sk)
{
	return (1 << sk->sk_state) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
}
static inline struct sock *sk_to_full_sk(struct sock *sk)
{
#ifdef CONFIG_INET
	if (sk && sk->sk_state == TCP_NEW_SYN_RECV)
		sk = inet_reqsk(sk)->rsk_listener;
#endif
	return sk;
}
bool actual_creator_uid(const struct sock *sk, u32 *uid)
{
	if (!sk || !uid || !sk_fullsock(sk))
		return false;
	if ((sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    !sk->sk_gta_creator_valid)
		return false;
	*uid = sk->sk_gta_creator_uid;
	return true;
}
static bool gta3xlwifi_socket_creator_uid(const struct sock* sk,u32* uid){assert(references==1);++gets;return actual_creator_uid(sk,uid);}
static void sock_gen_put(struct sock* sk){assert(references==1&&sk==returned);++puts;references=0;original.sk_gta_creator_uid=0;listener.sk_gta_creator_uid=0;original.sk_gta_creator_valid=listener.sk_gta_creator_valid=false;}
static struct sock* record(unsigned kind,struct net* net,const void* saddr,const void* daddr,size_t size,uint16_t sport,uint16_t dport,int index){
 assert(net==&fixture_net&&index==expected_ifindex&&kind==expected_kind);assert(sport==expected_tuple.sport&&dport==expected_tuple.dport);
 const void* expected_source=expected_tuple.family==AF_INET?(void*)&expected_tuple.address.v4.saddr:(void*)&expected_tuple.address.v6.saddr;
 const void* expected_dest=expected_tuple.family==AF_INET?(void*)&expected_tuple.address.v4.daddr:(void*)&expected_tuple.address.v6.daddr;
 assert(memcmp(saddr,expected_source,size)==0&&memcmp(daddr,expected_dest,size)==0);++lookups;assert(references==0);references=returned?1:0;return returned;
}
static struct sock* inet_lookup(struct net* n,struct inet_hashinfo* h,uint32_t s,uint16_t sp,uint32_t d,uint16_t dp,int i){assert(h==&tcp_hashinfo);return record(0,n,&s,&d,4,sp,dp,i);}
static struct sock* udp4_lib_lookup(struct net* n,uint32_t s,uint16_t sp,uint32_t d,uint16_t dp,int i){return record(1,n,&s,&d,4,sp,dp,i);}
static struct sock* inet6_lookup(struct net* n,struct inet_hashinfo* h,const struct in6_addr* s,uint16_t sp,const struct in6_addr* d,uint16_t dp,int i){assert(h==&tcp_hashinfo);return record(2,n,s,d,16,sp,dp,i);}
static struct sock* udp6_lib_lookup(struct net* n,const struct in6_addr* s,uint16_t sp,const struct in6_addr* d,uint16_t dp,int i){return record(3,n,s,d,16,sp,dp,i);}
bool gta3xlwifi_socket_peer_uid(struct net *net, int ifindex,
    const struct gta3xlwifi_socket_peer_tuple *tuple, u32 *uid)
{
    struct sock *original = NULL;
    struct sock *full;
    u32 found_uid;
    bool known;

    if (!net || !tuple || !uid || ifindex < 0)
        return false;
    switch (tuple->family) {
    case AF_INET:
        if (tuple->protocol == IPPROTO_TCP)
            original = inet_lookup(net, &tcp_hashinfo,
                tuple->address.v4.saddr, tuple->sport,
                tuple->address.v4.daddr, tuple->dport, ifindex);
        else if (tuple->protocol == IPPROTO_UDP)
            original = udp4_lib_lookup(net,
                tuple->address.v4.saddr, tuple->sport,
                tuple->address.v4.daddr, tuple->dport, ifindex);
        break;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        if (tuple->protocol == IPPROTO_TCP)
            original = inet6_lookup(net, &tcp_hashinfo,
                &tuple->address.v6.saddr, tuple->sport,
                &tuple->address.v6.daddr, tuple->dport, ifindex);
        else if (tuple->protocol == IPPROTO_UDP)
            original = udp6_lib_lookup(net,
                &tuple->address.v6.saddr, tuple->sport,
                &tuple->address.v6.daddr, tuple->dport, ifindex);
        break;
#endif
    default:
        break;
    }
    if (!original)
        return false;
    /* A request socket holds its listener reference. Read before releasing the
     * request; do not put the borrowed listener or return a raw socket pointer.
     */
    full = sk_to_full_sk(original);
    known = gta3xlwifi_socket_creator_uid(full, &found_uid);
    sock_gen_put(original);
    if (known)
        *uid = found_uid;
    return known;
}
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
int main(void){
 u32 out=0xaaaabbbb;struct gta3xlwifi_socket_peer_tuple tuple={.family=AF_INET,.protocol=IPPROTO_TCP,.sport=0x1234,.dport=0xabcd};
 T(!gta3xlwifi_socket_peer_uid(NULL,1,&tuple,&out)&&out==0xaaaabbbb);
 T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,NULL,&out)&&out==0xaaaabbbb);
 T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,&tuple,NULL));
 T(!gta3xlwifi_socket_peer_uid(&fixture_net,-1,&tuple,&out)&&out==0xaaaabbbb);
 tuple.family=1;T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,&tuple,&out)&&out==0xaaaabbbb);
 tuple.family=AF_INET;tuple.protocol=1;T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,&tuple,&out)&&out==0xaaaabbbb);
 tuple.family=AF_INET6;T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,&tuple,&out)&&out==0xaaaabbbb);
 T(!lookups&&!puts&&!gets&&!references);
 const u32 uids[]={0,65534,110001,0xffffffff};
 for(unsigned family=0;family<2;family++)for(unsigned protocol=0;protocol<2;protocol++)for(unsigned kind=0;kind<7;kind++)for(unsigned u=0;u<4;u++)for(unsigned index=0;index<3;index++){
  memset(&tuple,0,sizeof(tuple));tuple.family=family?AF_INET6:AF_INET;tuple.protocol=protocol?IPPROTO_UDP:IPPROTO_TCP;tuple.sport=0x1234;tuple.dport=0xabcd;
  if(family){for(unsigned j=0;j<16;j++){tuple.address.v6.saddr.s6_addr[j]=j+1;tuple.address.v6.daddr.s6_addr[j]=31-j;}}
  else{tuple.address.v4.saddr=0x01020304;tuple.address.v4.daddr=0x11223344;}
  expected_tuple=tuple;expected_ifindex=index==2?7:(int)index;expected_kind=family*2+protocol;
  original=(struct sock){TCP_ESTABLISHED,AF_INET6,uids[u],true};listener=(struct sock){TCP_LISTEN,AF_INET6,uids[u],true};request.rsk_listener=&listener;returned=&original;
  // Returned socket family may be AF_INET6 for IPv4 dual-stack lookup. Never
  // force family equality to the packet when reading trusted kernel results.
  if(kind==1)original.sk_gta_creator_valid=false;
  if(kind==2)original.sk_state=TCP_TIME_WAIT;
  if(kind>=3&&kind<=5){original.sk_state=TCP_NEW_SYN_RECV;if(kind==4)listener.sk_gta_creator_valid=false;if(kind==5)request.rsk_listener=NULL;}
  if(kind==6)returned=NULL;
  references=lookups=puts=gets=0;out=0xaaaabbbb;
  bool expected=kind==0||kind==3;bool known=gta3xlwifi_socket_peer_uid(&fixture_net,expected_ifindex,&tuple,&out);
  assert(known==expected&&out==(expected?uids[u]:0xaaaabbbb));++comparisons;
  assert(lookups==1&&references==0&&puts==(kind==6?0u:1u)&&gets==(kind==6?0u:1u));++comparisons;
 }
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
