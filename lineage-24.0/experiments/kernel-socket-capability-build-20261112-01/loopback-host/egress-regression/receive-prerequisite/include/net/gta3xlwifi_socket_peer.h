/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_GTA3XLWIFI_SOCKET_PEER_H
#define _NET_GTA3XLWIFI_SOCKET_PEER_H
#include <linux/types.h>
#include <linux/in6.h>
struct net;
struct gta3xlwifi_socket_peer_tuple {
    u16 family;
    u8 protocol;
    __be16 sport, dport;
    union {
        struct { __be32 saddr, daddr; } v4;
        struct { struct in6_addr saddr, daddr; } v6;
    } address;
};
/* Caller protects net lifetime and supplies a parsed, current packet tuple and
 * interface index. This does NOT decide packet eligibility, permission or
 * readiness. No result preserves output and must never be replaced with UID0.
 */
bool gta3xlwifi_socket_peer_uid(struct net *net, int ifindex,
    const struct gta3xlwifi_socket_peer_tuple *tuple, u32 *uid);
#endif
