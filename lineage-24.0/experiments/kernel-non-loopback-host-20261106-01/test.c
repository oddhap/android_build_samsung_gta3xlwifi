
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
#include <linux/netfilter/gta3xlwifi_owner_skip.h>
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
struct sk_buff{uint8_t data[1200];size_t length;int network;uint16_t protocol;};
struct net_device{unsigned ifindex;};
struct xt_action_param{const void* matchinfo;unsigned hooknum;const struct net_device* in;const struct net_device* out;};struct xt_mtchk_param{const void* matchinfo;unsigned family;};
static int failure=-1;
static int skb_network_offset(const struct sk_buff* skb){return skb->network;}
static int skb_copy_bits(const struct sk_buff* skb,int offset,void* out,int length){
 if(offset<0||offset==failure||(size_t)(offset+length)>skb->length){memset(out,0xa5,length);return -EFAULT;}
 memcpy(out,skb->data+offset,length);return 0;
}
static bool gta3xlwifi_owner_read(const struct sk_buff *skb, unsigned int offset,
                                  void *output, unsigned int length)
{
    if (skb_copy_bits(skb, skb_network_offset(skb) + offset, output, length)) {
        /* Android's load helper zeroes the entire destination on any error. */
        memset(output, 0, length);
        return false;
    }
    return true;
}
static bool gta3xlwifi_owner_skip_mt(const struct sk_buff *skb,
                                     struct xt_action_param *par)
{
    u8 protocol = 0, l4_offset = 0, flags = 0;
    struct { u8 protocol, length; } extension;

    if (!skb || (par->hooknum != NF_INET_LOCAL_IN &&
                 par->hooknum != NF_INET_LOCAL_OUT))
        return false;
    if (skb->protocol == htons(ETH_P_IP)) {
        gta3xlwifi_owner_read(skb, offsetof(struct iphdr, protocol), &protocol, 1);
        gta3xlwifi_owner_read(skb, 0, &l4_offset, 1);
        if (l4_offset < 0x45 || l4_offset > 0x4f)
            return false;
        l4_offset = (l4_offset & 0x0f) * 4;
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        gta3xlwifi_owner_read(skb, offsetof(struct ipv6hdr, nexthdr), &protocol, 1);
        l4_offset = sizeof(struct ipv6hdr);
        /* Match A17's exact parser: skip only ONE hop/destination option header.
         * Its offset is u8, including wrapping for long extension headers.
         */
        if (protocol == IPPROTO_HOPOPTS || protocol == IPPROTO_DSTOPTS) {
            if (gta3xlwifi_owner_read(skb, l4_offset, &extension, sizeof(extension))) {
                protocol = extension.protocol;
                l4_offset += (extension.length + 1) * 8;
            }
        }
    } else {
        return false;
    }
    if (protocol == IPPROTO_ESP)
        return true;
    if (protocol != IPPROTO_TCP)
        return false;
    /* Offset13 is the second TCP flags byte, as in A17 TCP_FLAG8_OFF. */
    gta3xlwifi_owner_read(skb, l4_offset + 13, &flags, 1);
    return (flags & 0x04) || (par->hooknum == NF_INET_LOCAL_IN && (flags & 0x01));
}
static int gta3xlwifi_owner_skip_check(const struct xt_mtchk_param *par)
{
    const struct gta3xlwifi_owner_skip_match *info = par->matchinfo;
    if (current_user_ns() != &init_user_ns || info->reserved ||
        (par->family != NFPROTO_IPV4 && par->family != NFPROTO_IPV6))
        return -EINVAL;
    return 0;
}
static bool gta3xlwifi_non_loopback_mt(const struct sk_buff *skb,
                                       struct xt_action_param *par)
{
    const struct net_device *device;
    if (!skb)
        return false;
    if (par->hooknum == NF_INET_LOCAL_IN)
        device = par->in;
    else if (par->hooknum == NF_INET_LOCAL_OUT)
        device = par->out;
    else
        return false;
    return !device || device->ifindex != 1;
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
#define TCP_FLAG8_FIN 0x01
#define TCP_FLAG8_RST 0x04
struct kver_uint{unsigned version;};struct egress_bool{bool egress;};
struct __sk_buff{const struct sk_buff* skb;uint16_t protocol;};
static long bpf_skb_load_bytes_net(const struct __sk_buff* skb,const int offset,void* out,const int length,const struct kver_uint kver){
 (void)kver;int result=skb_copy_bits(skb->skb,skb->skb->network+offset,out,length);if(result)memset(out,0,length);return result;
}
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
function bool skip_owner_match(const SkbIpPacketData* const packet,
                               const struct egress_bool egress) {
    if (packet->ip_version == 0) return false;

    if (packet->ip_proto == IPPROTO_ESP) return true;

    if (packet->ip_proto != IPPROTO_TCP) return false;

    // Always allow RST's, and additionally allow ingress FINs
    return packet->tcp_flags & (TCP_FLAG8_RST | (egress.egress ? 0 : TCP_FLAG8_FIN));
}
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
static void compare(struct sk_buff* skb){
 struct __sk_buff oracle={skb,skb->protocol};SkbIpPacketData parsed={0};
 (void)parse_skb(&parsed,&oracle,(struct kver_uint){515});
 for(unsigned hook=NF_INET_LOCAL_IN;hook<=NF_INET_LOCAL_OUT;hook+=2){
  struct xt_action_param p={.matchinfo=NULL,.hooknum=hook};struct egress_bool e={hook==NF_INET_LOCAL_OUT};
  bool expected=skip_owner_match(&parsed,e);bool actual=gta3xlwifi_owner_skip_mt(skb,&p);
  assert(actual==expected);++comparisons;
 }
}
int main(void){
 struct gta3xlwifi_owner_skip_match info={0};struct xt_mtchk_param c={&info,NFPROTO_IPV4};
 T(sizeof(info)==4);T(gta3xlwifi_owner_skip_check(&c)==0);c.family=NFPROTO_IPV6;T(gta3xlwifi_owner_skip_check(&c)==0);c.family=0;T(gta3xlwifi_owner_skip_check(&c)==-EINVAL);c.family=NFPROTO_IPV4;info.reserved=1;T(gta3xlwifi_owner_skip_check(&c)==-EINVAL);info.reserved=0;ns=&other_ns;T(gta3xlwifi_owner_skip_check(&c)==-EINVAL);ns=&init_user_ns;
 struct sk_buff skb={.length=1200};struct xt_action_param p={.matchinfo=&info,.hooknum=NF_INET_LOCAL_IN};T(!gta3xlwifi_owner_skip_mt(NULL,&p));p.hooknum=NF_INET_FORWARD;T(!gta3xlwifi_owner_skip_mt(&skb,&p));
 T(offsetof(struct tcphdr_with_flags16,flags16)+1==13);T(sizeof(struct ipv6hdr)==40);
 const uint8_t flags[]={0,1,2,4,5,16,255};
 for(int net=0;net<=14;net+=14){
  skb.network=net;skb.protocol=htons(ETH_P_IP);
  for(unsigned ihl=0;ihl<256;ihl++)for(unsigned proto=0;proto<256;proto++)for(unsigned f=0;f<sizeof(flags);f++){
   memset(skb.data,0,sizeof(skb.data));skb.data[net]=ihl;skb.data[net+9]=proto;
   unsigned offset=(ihl&15)*4;skb.data[net+offset+13]=flags[f];compare(&skb);
  }
  skb.protocol=htons(ETH_P_IPV6);
  for(unsigned first=0;first<256;first++)for(unsigned f=0;f<256;f++){
   memset(skb.data,0,sizeof(skb.data));skb.data[net+6]=first;skb.data[net+53]=f;compare(&skb);
  }
  for(unsigned ext=0;ext<2;ext++)for(unsigned proto=0;proto<256;proto++)for(unsigned len=0;len<256;len++)for(unsigned f=0;f<sizeof(flags);f++){
   memset(skb.data,0,sizeof(skb.data));skb.data[net+6]=ext?IPPROTO_DSTOPTS:IPPROTO_HOPOPTS;skb.data[net+40]=proto;skb.data[net+41]=len;
   uint8_t offset=(uint8_t)(40+(len+1)*8);skb.data[net+offset+13]=flags[f];compare(&skb);
  }
 }
 // Truncated headers/options and read failures must preserve zero-on-failure,
 // including failures after the IPv4 version or option next-protocol was read.
 for(unsigned variant=0;variant<6;variant++)for(unsigned length=0;length<310;length++){
  memset(skb.data,0,sizeof(skb.data));skb.network=14;skb.length=length;skb.protocol=htons(variant<2?ETH_P_IP:ETH_P_IPV6);
  skb.data[14]=0x45;skb.data[23]=variant?IPPROTO_TCP:IPPROTO_ESP;skb.data[20]=variant<4?IPPROTO_TCP:IPPROTO_HOPOPTS;
  skb.data[54]=IPPROTO_TCP;skb.data[55]=1;skb.data[47]=5;skb.data[67]=5;skb.data[83]=5;compare(&skb);
  skb.length=1200;failure=length;compare(&skb);failure=-1;
 }
 skb.protocol=0;compare(&skb);T(comparisons>5000000);
 struct net_device input={1},output={7};p.in=&input;p.out=&output;
 p.hooknum=NF_INET_LOCAL_IN;T(!gta3xlwifi_non_loopback_mt(&skb,&p));
 p.hooknum=NF_INET_LOCAL_OUT;T(gta3xlwifi_non_loopback_mt(&skb,&p));
 output.ifindex=1;input.ifindex=7;
 p.hooknum=NF_INET_LOCAL_IN;T(gta3xlwifi_non_loopback_mt(&skb,&p));
 p.hooknum=NF_INET_LOCAL_OUT;T(!gta3xlwifi_non_loopback_mt(&skb,&p));
 p.in=p.out=NULL;T(gta3xlwifi_non_loopback_mt(&skb,&p));
 p.hooknum=NF_INET_LOCAL_IN;T(gta3xlwifi_non_loopback_mt(&skb,&p));
 T(!gta3xlwifi_non_loopback_mt(NULL,&p));p.hooknum=NF_INET_FORWARD;
 T(!gta3xlwifi_non_loopback_mt(&skb,&p));
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
