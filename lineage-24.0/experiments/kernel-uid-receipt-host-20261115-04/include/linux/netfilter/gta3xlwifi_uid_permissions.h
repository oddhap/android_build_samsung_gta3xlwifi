/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_UID_PERMISSIONS_H
#define _UAPI_GTA3XLWIFI_UID_PERMISSIONS_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define GTA3XLWIFI_UID_IMAGE_VERSION 1U
#define GTA3XLWIFI_UID_IMAGE_MAX_ENTRIES 65536U
#define GTA3XLWIFI_UID_IMAGE_MAX_UID 0x7fffffffU
#define GTA3XLWIFI_UID_PERMISSION_MASK 0x7fU
#define GTA3XLWIFI_UID_NO_INTERNET (1U << 2)
/* Support bits describe real primitives, NEVER whole-network readiness. */
#define GTA3XLWIFI_UID_CAP_IMAGE (1U << 0)
#define GTA3XLWIFI_UID_CAP_CREATE4 (1U << 1)
#define GTA3XLWIFI_UID_CAP_CREATE6 (1U << 2)
struct gta3xlwifi_uid_permission_entry {
    __u32 uid;
    __u32 permissions;
};
/* Fixed24 bytes in native/compat userspace. SET is a full sorted sparse image;
 * revision must advance by1, or repeat an identical current image. GET with
 * count0/entries0 probes metadata; a data read supplies that exact revision.
 */
struct gta3xlwifi_uid_permission_transfer {
    __u32 version;
    __u32 count;
    __aligned_u64 revision;
    __aligned_u64 entries;
};
#define GTA3XLWIFI_UID_FEATURES _IO('g', 0x54)
#define GTA3XLWIFI_UID_SET_IMAGE _IOW('g', 0x55, struct gta3xlwifi_uid_permission_transfer)
#define GTA3XLWIFI_UID_GET_IMAGE _IOWR('g', 0x56, struct gta3xlwifi_uid_permission_transfer)
#endif
