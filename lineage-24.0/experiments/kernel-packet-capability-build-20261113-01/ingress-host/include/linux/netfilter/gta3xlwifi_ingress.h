/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_INGRESS_H
#define _UAPI_GTA3XLWIFI_INGRESS_H
#include <linux/types.h>
#define GTA3XLWIFI_BAD_IIF_MATCH "gta3xlwifi_bad_iif"
#define GTA3XLWIFI_INGRESS_DISCARD_MATCH "gta3xlwifi_ingress_discard"
struct gta3xlwifi_bad_iif_match {
    /* 0 means reject every non-loopback/non-DNS input (lockdown without IIF).
     * An explicitly present wildcard IIF=0 is represented by NO drop rule. */
    __u32 allowed_ifindex;
    __u32 reserved;
};
struct gta3xlwifi_ingress_discard_match {
    __u8 daddr[16];  /* IPv4 uses exact IPv4-mapped IPv6 representation. */
    __u32 allowed_ifindex[2];
    __u32 reserved;
};
#endif
