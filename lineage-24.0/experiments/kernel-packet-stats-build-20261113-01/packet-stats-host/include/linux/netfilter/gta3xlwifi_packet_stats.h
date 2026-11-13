/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_PACKET_STATS_H
#define _UAPI_GTA3XLWIFI_PACKET_STATS_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define GTA3XLWIFI_PACKET_STATS_VERSION 1U
#define GTA3XLWIFI_PACKET_STATS_MAX 5000U
#define GTA3XLWIFI_APP_STATS_MAX 10000U
#define GTA3XLWIFI_COUNTERSET_MAX 20000U
/* Storage/control primitive only. NO actual packet-hook/Ready claim. */
#define GTA3XLWIFI_UID_CAP_PACKET_STATS_STORE (1U << 12)
#define GTA3XLWIFI_STATS_BANK_A 0U
#define GTA3XLWIFI_STATS_BANK_B 1U
#define GTA3XLWIFI_STATS_APP_UID 2U
struct gta3xlwifi_stats_key { __u32 uid, tag, counterset, ifindex; };
struct gta3xlwifi_packet_stats_entry {
    struct gta3xlwifi_stats_key key;
    __aligned_u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
};
struct gta3xlwifi_app_stats_entry {
    __u32 uid, reserved;
    __aligned_u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
};
struct gta3xlwifi_packet_stats_state {
    __u32 version, active_bank;
    __aligned_u64 active_epoch;
    __u32 bank_count[2], app_count, counterset_count;
    __aligned_u64 bank_epoch[2], bank_lost[2], app_lost, total_stats_lost;
    __u32 pending_mask, reserved;
};
/* Non-consuming one-call snapshot: capacity5000 for frozen bank,10000 for app.
 * Input reserved/lost_updates/sequence must0. count0+entries0 probes only.
 * Frozen bank requires pending and exact epoch. APP_UID input epoch must0.
 * Loss counts real failed update attempts, not estimated lost packets.
 */
struct gta3xlwifi_packet_stats_transfer {
    __u32 version, kind;
    __aligned_u64 epoch;
    __u32 count, reserved;
    __aligned_u64 entries, lost_updates, sequence;
};
/* Input active_bank/active_epoch are CAS. Other input fields must0. On success
 * returns NEW active state plus frozen previous bank/epoch. A copy failure can
 * follow a real commit: never blindly retry; inspect STATE to recover.
 */
struct gta3xlwifi_packet_stats_swap {
    __u32 version, active_bank;
    __aligned_u64 active_epoch;
    __u32 inactive_bank, reserved;
    __aligned_u64 inactive_epoch;
};
/* Explicit drain ACK only after the full frozen snapshot has been delivered.
 * Epoch ACK is idempotent, never clears active/new-generation counters.
 */
struct gta3xlwifi_packet_stats_ack {
    __u32 version, bank;
    __aligned_u64 epoch, reserved;
};
#define GTA3XLWIFI_STATS_SET_COUNTERSET 1U
#define GTA3XLWIFI_STATS_DELETE_UID 2U
/* SET_COUNTERSET accepts0(default/delete) or1(foreground), tag must0.
 * DELETE_UID clears both stats banks/app/counterset, NOT socket tag metadata.
 * It requires no pending frozen batch, matching poll/ACK-before-UID-removal.
 */
struct gta3xlwifi_packet_stats_edit {
    __u32 version, operation, uid, tag, counterset, reserved;
};
#define GTA3XLWIFI_STATS_GET_STATE _IOR('g',0x5b,struct gta3xlwifi_packet_stats_state)
#define GTA3XLWIFI_STATS_READ _IOWR('g',0x5c,struct gta3xlwifi_packet_stats_transfer)
#define GTA3XLWIFI_STATS_SWAP _IOWR('g',0x5d,struct gta3xlwifi_packet_stats_swap)
#define GTA3XLWIFI_STATS_ACK _IOW('g',0x5e,struct gta3xlwifi_packet_stats_ack)
#define GTA3XLWIFI_STATS_EDIT _IOW('g',0x5f,struct gta3xlwifi_packet_stats_edit)
#endif
