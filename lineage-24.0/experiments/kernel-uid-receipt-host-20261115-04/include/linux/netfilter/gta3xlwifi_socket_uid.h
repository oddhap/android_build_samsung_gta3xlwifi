/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_SOCKET_UID_H
#define _UAPI_GTA3XLWIFI_SOCKET_UID_H
#include <linux/types.h>
#define GTA3XLWIFI_RAW_UID_MATCH "gta3xlwifi_raw_uid"
#define GTA3XLWIFI_RAW_APPID_MATCH "gta3xlwifi_raw_appid"
struct gta3xlwifi_socket_uid_match {
	__u32 minimum;
	__u32 maximum;
};
#endif
