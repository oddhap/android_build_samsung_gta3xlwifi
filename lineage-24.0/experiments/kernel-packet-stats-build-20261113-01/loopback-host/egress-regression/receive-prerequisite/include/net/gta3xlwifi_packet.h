/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_GTA3XLWIFI_PACKET_H
#define _NET_GTA3XLWIFI_PACKET_H
#include <linux/types.h>
#include <linux/in6.h>
struct sk_buff;
/* Exact A17 SkbIpPacketData layout. Parser initializes the whole output. */
struct gta3xlwifi_packet {
    struct in6_addr saddr, daddr;
    __be16 sport, dport;
    u8 ip_proto, tcp_flags, ip_version, pad;
};
bool gta3xlwifi_parse_packet(const struct sk_buff *skb, struct gta3xlwifi_packet *packet);
#endif
