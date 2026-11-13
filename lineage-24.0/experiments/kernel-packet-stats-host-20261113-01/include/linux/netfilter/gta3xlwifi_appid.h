/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_APPID_H
#define _UAPI_GTA3XLWIFI_APPID_H
#include <linux/types.h>
#define GTA3XLWIFI_APPID_MATCH "gta3xlwifi_appid"
#define GTA3XLWIFI_APPID_USER_OFFSET 100000U
struct gta3xlwifi_appid_match {
	__u32 minimum;
	__u32 maximum;
};
#endif
