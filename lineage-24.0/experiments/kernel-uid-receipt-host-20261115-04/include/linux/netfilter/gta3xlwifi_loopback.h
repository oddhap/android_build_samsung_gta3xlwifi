/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_GTA3XLWIFI_LOOPBACK_H
#define _UAPI_GTA3XLWIFI_LOOPBACK_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define GTA3XLWIFI_LOOPBACK_VERSION 1U
#define GTA3XLWIFI_LOOPBACK_MAX_EVENTS 512U
#define GTA3XLWIFI_UID_CAP_LOOPBACK (1U << 7) /* real check/event/read primitive only */
#define GTA3XLWIFI_LOOPBACK_ALLOWED 0U
#define GTA3XLWIFI_LOOPBACK_BLOCKED 1U
/* Genuine packet-derived event. Sequence/boot clock/loss are diagnostic stream
 * metadata; the src/dst/result payload matches A17 LoopbackAccessEvent values.
 */
struct gta3xlwifi_loopback_event {
    __u32 sender_uid, receiver_uid, result, reserved;
    __aligned_u64 boottime_ns;
    __aligned_u64 sequence;
    __aligned_u64 lost_events;
};
/* count0/entries0 probes queue metadata. A consuming data read supplies the
 * probed first_sequence and capacity1..512. Returns up to capacity records and
 * actual current loss count. Both user copies must succeed before consumption.
 * Sole authenticated lease owner only. No enable/disable or injection API.
 */
struct gta3xlwifi_loopback_transfer {
    __u32 version, count;
    __aligned_u64 entries;
    __aligned_u64 first_sequence;
    __aligned_u64 lost_events;
};
#define GTA3XLWIFI_LOOPBACK_GET_EVENTS _IOWR('g', 0x59, struct gta3xlwifi_loopback_transfer)
#endif
