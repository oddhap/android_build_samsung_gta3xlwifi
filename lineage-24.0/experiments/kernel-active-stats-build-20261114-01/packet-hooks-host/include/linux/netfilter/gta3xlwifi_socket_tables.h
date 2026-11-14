/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_SOCKET_TABLES_H
#define _UAPI_GTA3XLWIFI_SOCKET_TABLES_H
/* UID_FEATURES: registered private IPv4+IPv6 tables and exact-skb UID snapshot.
 * Does not assert hooks, rules, full owner policy, BPF support or readiness.
 */
#define GTA3XLWIFI_UID_CAP_SOCKET_TABLES (1U << 8)
/* Both registered private ingress matches plus exact-skb DNS/direction context.
 * This bit does not assert installed IIF/VPN/ingress-discard rules or readiness. */
#define GTA3XLWIFI_UID_CAP_INGRESS_MATCHES (1U << 9)
#endif
