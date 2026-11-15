/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_IFACE_STATS_H
#define _UAPI_GTA3XLWIFI_IFACE_STATS_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define GTA3XLWIFI_IFACE_STATS_VERSION 1U
#define GTA3XLWIFI_IFACE_STATS_MAX 1000U
#define GTA3XLWIFI_IFACE_STATS_MATCH "gta3xlwifi_iface_stats"
#define GTA3XLWIFI_UID_CAP_IFACE_STATS (1U << 10)
/* Real compiled IPv4+IPv6 postrouting correction, not accounting activation. */
#define GTA3XLWIFI_UID_CAP_IFACE_DROP_UNDO (1U << 11)
struct gta3xlwifi_iface_stats_match { __u32 output; __u32 reserved; };
struct gta3xlwifi_iface_stats_entry {
    __u32 ifindex; __u32 reserved;
    __aligned_u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
};
/* Non-consuming single snapshot. Input lost_updates/update_sequence MUST be0.
 * count0+entries0 probes metadata only. A caller needing consistent records
 * supplies capacity1000 in ONE call; there is no probe/data revision race.
 * Lost updates saturate at U64_MAX; sequence is opaque modulo2^64.
 */
struct gta3xlwifi_iface_stats_transfer {
    __u32 version, count;
    __aligned_u64 entries, lost_updates, update_sequence;
};
#define GTA3XLWIFI_IFACE_STATS_GET _IOWR('g',0x5a,struct gta3xlwifi_iface_stats_transfer)
/* Genuine kernel-lifetime interface-name history, append-only private ABI.
 * NETDEV_REGISTER/CHANGENAME update the current name for an ifindex; unregister
 * retains it, as the A17 persistent iface-index/name map. No packet counters or
 * BPF-loaded/whole-network readiness signal is invented by this history.
 */
#define GTA3XLWIFI_UID_CAP_IFACE_NAMES (1U << 16)
#define GTA3XLWIFI_IFACE_NAMES_VERSION 1U
struct gta3xlwifi_iface_name_entry { __u32 ifindex; char name[16]; };
struct gta3xlwifi_iface_names_transfer {
    __u32 version, count;
    __aligned_u64 entries, lost_updates, update_sequence;
};
#define GTA3XLWIFI_IFACE_NAMES_GET _IOWR('g',0x62,struct gta3xlwifi_iface_names_transfer)
#endif
