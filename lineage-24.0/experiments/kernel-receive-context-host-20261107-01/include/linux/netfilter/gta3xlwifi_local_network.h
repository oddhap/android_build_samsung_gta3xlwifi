/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_LOCAL_NETWORK_H
#define _UAPI_GTA3XLWIFI_LOCAL_NETWORK_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define GTA3XLWIFI_LNA_VERSION 1U
#define GTA3XLWIFI_LNA_MAX_ENTRIES 1000U
#define GTA3XLWIFI_LNA_KEY_BYTES 24U
#define GTA3XLWIFI_LNA_KEY_BITS 192U
/* A compiled real store primitive, NEVER complete networking readiness. */
#define GTA3XLWIFI_UID_CAP_LNA_STORE (1U << 3)
#define GTA3XLWIFI_UID_CAP_LNA_MATCH (1U << 4)
/* Socket-aware receive LNA/shared gate only, not complete firewall readiness. */
#define GTA3XLWIFI_UID_CAP_LNA_RECEIVE (1U << 5)
#define GTA3XLWIFI_LNA_MATCH "gta3xlwifi_lna"
struct gta3xlwifi_lna_match { __u32 reserved; };
/* Canonical prefix: unused low bits/bytes are zero. Sort by prefix_bits then
 * memcmp(key); duplicate prefixes are rejected. Native-order UID/ifindex/u16
 * protocol, network-order address/port bytes match the actual A17 key payload.
 */
struct gta3xlwifi_lna_entry {
    __u32 prefix_bits;
    __u8 key[GTA3XLWIFI_LNA_KEY_BYTES];
    __u8 allowed;
    __u8 reserved[3];
};
struct gta3xlwifi_lna_transfer {
    __u32 version;
    __u32 network_count;
    __u32 host_count;
    __u32 reserved;
    __aligned_u64 revision;
    __aligned_u64 network_entries;
    __aligned_u64 host_entries;
};
/* SET: full image, held owner lease only, revision+1 or identical replay.
 * GET: both count/pointer pairs zero probes metadata; a data read supplies
 * the exact probed revision and capacity for BOTH actual tables.
 */
#define GTA3XLWIFI_LNA_SET_IMAGE _IOW('g', 0x57, struct gta3xlwifi_lna_transfer)
#define GTA3XLWIFI_LNA_GET_IMAGE _IOWR('g', 0x58, struct gta3xlwifi_lna_transfer)
#endif
