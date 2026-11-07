
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/netfilter/gta3xlwifi_local_network.h>
#include <net/gta3xlwifi_packet.h>
typedef uint8_t u8;
#define function static
#define NF_INET_LOCAL_IN 1
#define NF_INET_FORWARD 2
#define NF_INET_LOCAL_OUT 3
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
static uint16_t htons(uint16_t x){return __builtin_bswap16(x);}
static uint32_t htonl(uint32_t x){return __builtin_bswap32(x);}
struct user_namespace{int unused;};static struct user_namespace init_user_ns,other_ns;static struct user_namespace* ns=&init_user_ns;
static struct user_namespace* current_user_ns(void){return ns;}
struct sk_buff{uint8_t data[1200];size_t length;int network;uint16_t protocol;struct dst_entry* dst;struct sock* sk;};
struct net_device{unsigned ifindex;};
struct dst_entry{struct net_device* dev;};
static struct dst_entry* skb_dst(const struct sk_buff* skb){return skb->dst;}
struct xt_action_param{const void* matchinfo;unsigned hooknum;const struct net_device* in;const struct net_device* out;};struct xt_mtchk_param{const void* matchinfo;unsigned family;};
static int failure=-1;
static int skb_network_offset(const struct sk_buff* skb){return skb->network;}
static int skb_copy_bits(const struct sk_buff* skb,int offset,void* out,int length){
 if(offset<0||offset==failure||(size_t)(offset+length)>skb->length){memset(out,0xa5,length);return -EFAULT;}
 memcpy(out,skb->data+offset,length);return 0;
}

typedef uint32_t u32;typedef uint16_t u16;typedef uint32_t uid_t;
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define NFPROTO_UNSPEC 0
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) do{(x)=(v);}while(0)
static uid_t overflowuid=65534;
struct net{struct user_namespace*user_ns;};struct sock{u32 uid;bool full;struct net*net;};
static struct sock* skb_to_full_sk(const struct sk_buff*s){return s->sk&&s->sk->full?s->sk:NULL;}
static bool sk_fullsock(const struct sock*s){return s->full;}
static struct net* sock_net(struct sock*s){return s->net;}
static u32 sock_net_uid(struct net*n,struct sock*s){assert(n==s->net);return s->uid;}
static u32 from_kuid_munged(struct user_namespace*n,u32 u){assert(n==&init_user_ns||n==&other_ns);return u;}
static u32 expected_uid,expected_index;static struct in6_addr expected_remote;static u16 expected_proto;static __be16 expected_port;static unsigned decisions;static bool decision;
static bool gta3xlwifi_lna_blocked(u32 uid,u32 index,const struct in6_addr*ip,u16 proto,__be16 port){assert(uid==expected_uid&&index==expected_index&&!memcmp(ip,&expected_remote,16)&&proto==expected_proto&&port==expected_port);++decisions;return decision;}
struct xt_match{const char*name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void*me;};

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
static bool gta3xlwifi_lna_registered;
u32 gta3xlwifi_lna_packet_features(void)
{
    return READ_ONCE(gta3xlwifi_lna_registered) ? GTA3XLWIFI_UID_CAP_LNA_MATCH : 0;
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
static int gta3xlwifi_lna_check(const struct xt_mtchk_param *par)
{
    const struct gta3xlwifi_lna_match *info = par->matchinfo;
    if (current_user_ns() != &init_user_ns || info->reserved ||
        (par->family != NFPROTO_IPV4 && par->family != NFPROTO_IPV6))
        return -EINVAL;
    return 0;
}
static struct xt_match gta3xlwifi_lna_reg __read_mostly = {
    .name = GTA3XLWIFI_LNA_MATCH,
    .revision = 0,
    .family = NFPROTO_UNSPEC,
    .hooks = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_LOCAL_OUT),
    .match = gta3xlwifi_lna_mt,
    .checkentry = gta3xlwifi_lna_check,
    .matchsize = sizeof(struct gta3xlwifi_lna_match),
    .me = THIS_MODULE,
};

static int registration_error;static unsigned registrations;static int xt_register_match(struct xt_match*m){assert(m==&gta3xlwifi_lna_reg);++registrations;return registration_error;}
static int __init gta3xlwifi_lna_init(void)
{
    int result = xt_register_match(&gta3xlwifi_lna_reg);
    if (!result)
        WRITE_ONCE(gta3xlwifi_lna_registered, true);
    return result;
}
struct tcphdr_with_flags16 {
  __be16 source;
  __be16 dest;
  __be32 seq;
  __be32 ack_seq;
  __extension__ union {
    __be16 flags16;
    struct {
      // copied from //external/iproute2/include/uapi/linux/tcp.h
#if defined(__LITTLE_ENDIAN_BITFIELD)
      __u16 rsvd:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
      __u16 doff:4, rsvd:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
    };
  };
  __be16 window;
  __sum16 check;
  __be16 urg_ptr;
};
typedef struct {
    struct in6_addr saddr; // Stores v6 or v4-mapped-v6
    struct in6_addr daddr; // Stores v6 or v4-mapped-v6
    __be16 sport;
    __be16 dport;
    uint8_t ip_proto;
    uint8_t tcp_flags;
    uint8_t ip_version;
    uint8_t pad;
} SkbIpPacketData;

#define TCP_OFFSET(field) offsetof(struct tcphdr_with_flags16, field)
#define IP4_OFFSET(field) offsetof(struct iphdr, field)
#define IP6_OFFSET(field) offsetof(struct ipv6hdr, field)
#define IPPROTO_IHL_OFF 0
#define TCP_FLAG8_OFF (TCP_OFFSET(flags16) + 1)
struct kver_uint{unsigned version;};struct __sk_buff{const struct sk_buff*skb;uint16_t protocol;};
static long bpf_skb_load_bytes_net(const struct __sk_buff*s,const int offset,void*out,const int len,const struct kver_uint k){(void)k;int result=skb_copy_bits(s->skb,s->skb->network+offset,out,len);if(result)memset(out,0,len);return result;}
function bool parse_skb(SkbIpPacketData *const packet,
                        const struct __sk_buff *const skb,
                        const struct kver_uint kver) {
    // Errors from bpf_skb_load_bytes_net are ignored to favor returning
    // something over returning nothing. In the event of an error, the kernel
    // will fill in zero for the destination memory.
    uint8_t proto = 0;
    uint8_t L4_off = 0;
    if (skb->protocol == htons(ETH_P_IP)) {
        packet->ip_version = 4;
        packet->saddr.s6_addr32[2] = htonl(0xFFFF);
        (void)bpf_skb_load_bytes_net(skb, IP4_OFFSET(saddr),
                                     &packet->saddr.s6_addr32[3],
                                     sizeof(__be32), kver);

        packet->daddr.s6_addr32[2] = htonl(0xFFFF);
        (void)bpf_skb_load_bytes_net(skb, IP4_OFFSET(daddr),
                                     &packet->daddr.s6_addr32[3],
                                     sizeof(__be32), kver);

        (void)bpf_skb_load_bytes_net(skb, IP4_OFFSET(protocol), &proto,
                                     sizeof(proto), kver);
        // IHL calculation
        (void)bpf_skb_load_bytes_net(skb, IPPROTO_IHL_OFF, &L4_off,
                                     sizeof(L4_off), kver);
        if (L4_off < 0x45 || L4_off > 0x4F) return false;
        L4_off = (L4_off & 0x0F) * 4;
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        packet->ip_version = 6;
        (void)bpf_skb_load_bytes_net(skb, IP6_OFFSET(saddr), &packet->saddr,
                                     sizeof(packet->saddr), kver);
        (void)bpf_skb_load_bytes_net(skb, IP6_OFFSET(daddr), &packet->daddr,
                                     sizeof(packet->daddr), kver);
        (void)bpf_skb_load_bytes_net(skb, IP6_OFFSET(nexthdr), &proto,
                                     sizeof(proto), kver);
        L4_off = sizeof(struct ipv6hdr);
        // skip over a *single* HOPOPTS or DSTOPTS extension header (if present)
        if (proto == IPPROTO_HOPOPTS || proto == IPPROTO_DSTOPTS) {
            struct {
                uint8_t proto, len;
            } ext_hdr;
            if (!bpf_skb_load_bytes_net(skb, L4_off, &ext_hdr, sizeof(ext_hdr), kver)) {
                proto = ext_hdr.proto;
                L4_off += (ext_hdr.len + 1) * 8;
            }
        }
    } else {
        // Not an IP packet. Don't continue parsing.
        return false;
    }
    packet->ip_proto = proto;

    switch (proto) {
        case IPPROTO_TCP:
            (void)bpf_skb_load_bytes_net(skb, L4_off + TCP_FLAG8_OFF,
                                         &packet->tcp_flags,
                                         sizeof(packet->tcp_flags), kver);
            // fallthrough
        case IPPROTO_DCCP:
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
        case IPPROTO_SCTP:
            (void)bpf_skb_load_bytes_net(skb, L4_off + 0, &packet->sport,
                                         sizeof(packet->sport), kver);
            (void)bpf_skb_load_bytes_net(skb, L4_off + 2, &packet->dport,
                                         sizeof(packet->dport), kver);
            break;
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            // Both IPv4 and IPv6 icmp start with u8 type & code, which we store
            // in the bottom (ie. second) byte of sport/dport (which are be16s),
            // the top byte is already zero.
            (void)bpf_skb_load_bytes_net(skb, L4_off + 0,
                                         (char *)&packet->sport + 1, 1,
                                         kver); // type
            (void)bpf_skb_load_bytes_net(skb, L4_off + 1,
                                         (char *)&packet->dport + 1, 1,
                                         kver); // code
            break;
    }
    return true;
}

static unsigned cases,comparisons,dispatches;
#define T(x) do{assert(x);++cases;}while(0)
static struct net net={&init_user_ns};static struct sock socket={10001,true,&net};
static struct net_device input={17},stale={777},routed={7};static struct dst_entry route={&routed};
static void compare(struct sk_buff*skb){
 SkbIpPacketData expected={0};struct __sk_buff ob={skb,skb->protocol};bool parsed=parse_skb(&expected,&ob,(struct kver_uint){515});
 struct gta3xlwifi_packet actual;memset(&actual,0x5a,sizeof(actual));bool result=gta3xlwifi_parse_packet(skb,&actual);assert(parsed==result&&!memcmp(&actual,&expected,40));++comparisons;
 const u32 uids[]={0,1000,9999,10001,65534,100001,101000,0xffffffff};socket.uid=uids[comparisons%8];socket.full=comparisons%3!=0;skb->sk=comparisons%5?&socket:NULL;net.user_ns=comparisons%2?&init_user_ns:&other_ns;overflowuid=comparisons%11?65534:777;
 skb->dst=comparisons%7?&route:NULL;
 for(unsigned hook=1;hook<=3;hook+=2){
  struct xt_action_param p={.hooknum=hook,.in=comparisons%9?&input:NULL,.out=&stale};
  expected_uid=skb->sk&&socket.full?socket.uid:overflowuid;if(expected_uid==65534)expected_uid=0;
  expected_index=hook==3?(skb->dst?routed.ifindex:0):(p.in?input.ifindex:0);expected_remote=hook==3?expected.daddr:expected.saddr;expected_proto=expected.ip_proto;expected_port=hook==3?expected.dport:expected.sport;decisions=0;decision=comparisons&1;
  assert(gta3xlwifi_lna_mt(skb,&p)==(parsed&&decision)&&decisions==parsed);++dispatches;
 }
}
int main(void){
 T(sizeof(struct gta3xlwifi_packet)==40&&sizeof(SkbIpPacketData)==40);T(sizeof(struct gta3xlwifi_lna_match)==4);
 struct gta3xlwifi_lna_match info={0};struct xt_mtchk_param chk={&info,NFPROTO_IPV4};T(gta3xlwifi_lna_check(&chk)==0);chk.family=NFPROTO_IPV6;T(gta3xlwifi_lna_check(&chk)==0);chk.family=0;T(gta3xlwifi_lna_check(&chk)==-EINVAL);chk.family=NFPROTO_IPV4;info.reserved=1;T(gta3xlwifi_lna_check(&chk)==-EINVAL);info.reserved=0;ns=&other_ns;T(gta3xlwifi_lna_check(&chk)==-EINVAL);ns=&init_user_ns;
 T(gta3xlwifi_lna_packet_features()==0);registration_error=-ENOMEM;T(gta3xlwifi_lna_init()==-ENOMEM&&gta3xlwifi_lna_packet_features()==0);registration_error=0;T(gta3xlwifi_lna_init()==0&&gta3xlwifi_lna_packet_features()==16&&registrations==2);
 T(gta3xlwifi_lna_reg.match==gta3xlwifi_lna_mt&&gta3xlwifi_lna_reg.hooks==((1<<1)|(1<<3))&&gta3xlwifi_lna_reg.matchsize==4&&!strcmp(gta3xlwifi_lna_reg.name,"gta3xlwifi_lna"));
 struct sk_buff skb={.length=1200};struct xt_action_param p={.hooknum=1};T(!gta3xlwifi_lna_mt(NULL,&p));T(!gta3xlwifi_lna_mt(&skb,NULL));p.hooknum=2;T(!gta3xlwifi_lna_mt(&skb,&p));struct gta3xlwifi_packet actual;T(!gta3xlwifi_parse_packet(NULL,&actual));T(!gta3xlwifi_parse_packet(&skb,NULL));
 const u8 flags[]={0,1,2,4,5,16,255};
 for(int netoff=0;netoff<=14;netoff+=14){
  skb.network=netoff;skb.protocol=htons(ETH_P_IP);
  for(unsigned ihl=0;ihl<256;ihl++)for(unsigned proto=0;proto<256;proto++)for(unsigned f=0;f<sizeof(flags);f++){
   for(unsigned b=0;b<sizeof(skb.data);b++)skb.data[b]=(b*7+proto+f)&255;skb.data[netoff]=ihl;skb.data[netoff+9]=proto;skb.data[netoff+(ihl&15)*4+13]=flags[f];compare(&skb);
  }
  skb.protocol=htons(ETH_P_IPV6);
  for(unsigned first=0;first<256;first++)for(unsigned f=0;f<256;f++){
   for(unsigned b=0;b<sizeof(skb.data);b++)skb.data[b]=(b*3+first+f)&255;skb.data[netoff+6]=first;skb.data[netoff+53]=f;compare(&skb);
  }
  for(unsigned ext=0;ext<2;ext++)for(unsigned proto=0;proto<256;proto++)for(unsigned len=0;len<256;len++)for(unsigned f=0;f<sizeof(flags);f++){
   for(unsigned b=0;b<sizeof(skb.data);b++)skb.data[b]=(b*5+proto+f)&255;skb.data[netoff+6]=ext?IPPROTO_DSTOPTS:IPPROTO_HOPOPTS;skb.data[netoff+40]=proto;skb.data[netoff+41]=len;u8 off=(u8)(40+(len+1)*8);skb.data[netoff+off+13]=flags[f];compare(&skb);
  }
 }
 for(unsigned variant=0;variant<6;variant++)for(unsigned length=0;length<310;length++){
  skb.network=14;skb.length=length;skb.protocol=htons(variant<2?ETH_P_IP:ETH_P_IPV6);for(unsigned b=0;b<sizeof(skb.data);b++)skb.data[b]=b*11;skb.data[14]=0x45;skb.data[23]=variant?IPPROTO_TCP:IPPROTO_ESP;skb.data[20]=variant<4?IPPROTO_TCP:IPPROTO_HOPOPTS;skb.data[54]=IPPROTO_ICMPV6;skb.data[55]=1;compare(&skb);skb.length=1200;failure=length;compare(&skb);failure=-1;
 }
 skb.protocol=0;compare(&skb);T(comparisons>2800000&&dispatches==2*comparisons);
 printf("passed_cases=%u parser_comparisons=%u endpoint_dispatches=%u\n",cases,comparisons,dispatches);
}
