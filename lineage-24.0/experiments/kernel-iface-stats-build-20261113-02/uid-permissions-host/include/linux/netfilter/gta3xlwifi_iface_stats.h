/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_IFACE_STATS_H
#define _UAPI_GTA3XLWIFI_IFACE_STATS_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define GTA3XLWIFI_IFACE_STATS_VERSION 1U
#define GTA3XLWIFI_IFACE_STATS_MAX 1000U
#define GTA3XLWIFI_IFACE_STATS_MATCH "gta3xlwifi_iface_stats"
#define GTA3XLWIFI_UID_CAP_IFACE_STATS (1U << 10)
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
#endif
