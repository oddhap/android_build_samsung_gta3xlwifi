/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_RUNTIME_POLICY_H
#define _UAPI_GTA3XLWIFI_RUNTIME_POLICY_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define GTA3XLWIFI_RUNTIME_VERSION 1U
#define GTA3XLWIFI_RUNTIME_MAX_BLOCKED_UIDS 1000U
#define GTA3XLWIFI_RUNTIME_LOOPBACK_CHECKS 1U
#define GTA3XLWIFI_RUNTIME_LOOPBACK_METRICS 2U
#define GTA3XLWIFI_RUNTIME_PERMISSION_PROPAGATION 4U
#define GTA3XLWIFI_RUNTIME_FLAG_MASK 7U
#define GTA3XLWIFI_RUNTIME_CONFIGURED 1U
#define GTA3XLWIFI_UID_CAP_RUNTIME_POLICY (1U << 14)
/* Entries are sorted unique u32 UIDs with true legacy local-net blocking.
 * False/absent map values are equivalent for this A17 predicate.
 * GET input flags/status must0; count0+entries0 queries metadata. Data requires
 * matching nonzero revision. Revision0 is uninitialized, never configured-off.
 * SET status must0; revision is next current+1, or exact idempotent receipt.
 * A successful SET confirms configuration for THIS lease. Open/close invalidates
 * that confirmation while preserving real image metadata for explicit recovery.
 */
struct gta3xlwifi_runtime_transfer {
    __u32 version, count, flags, status;
    __aligned_u64 revision, entries;
};
#define GTA3XLWIFI_RUNTIME_GET _IOWR('g',0x60,struct gta3xlwifi_runtime_transfer)
#define GTA3XLWIFI_RUNTIME_SET _IOW('g',0x61,struct gta3xlwifi_runtime_transfer)
#endif
