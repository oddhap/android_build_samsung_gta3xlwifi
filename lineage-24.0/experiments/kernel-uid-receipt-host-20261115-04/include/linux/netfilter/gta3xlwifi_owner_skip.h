/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_OWNER_SKIP_H
#define _UAPI_GTA3XLWIFI_OWNER_SKIP_H
#include <linux/types.h>
#define GTA3XLWIFI_OWNER_SKIP_MATCH "gta3xlwifi_owner_skip"
#define GTA3XLWIFI_NON_LOOPBACK_MATCH "gta3xlwifi_non_loopback"
struct gta3xlwifi_owner_skip_match {
    __u32 reserved;
};
#endif
