/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_NETPOLICY_H
#define _UAPI_GTA3XLWIFI_NETPOLICY_H
#include <linux/ioctl.h>
#include <linux/types.h>

#define GTA3XLWIFI_NETPOLICY_VERSION 1
#define GTA3XLWIFI_NETPOLICY_ABI     _IO('g', 0x50)
#define GTA3XLWIFI_NETPOLICY_HOLD    _IO('g', 0x51)
#define GTA3XLWIFI_NETPOLICY_RELEASE _IO('g', 0x52)
#define GTA3XLWIFI_NETPOLICY_STATE   _IO('g', 0x53)
#define GTA3XLWIFI_NETPOLICY_MATCH "gta3xlwifi_guard"

/* No pointers or arguments: identical ioctl numbers on ARM32 and ARM64.
 * ABI returns VERSION; STATE returns 1 when held, 0 when released.
 * All other successful commands return 0. Every argument must be zero.
 * Opening exclusively acquires a closed lease. Owner close/exit closes the
 * barrier even if forked children still hold the file. This neither installs
 * rules nor proves complete networking readiness.
 */
struct gta3xlwifi_netpolicy_match {
	__u8 reserved[4];
};
#endif
