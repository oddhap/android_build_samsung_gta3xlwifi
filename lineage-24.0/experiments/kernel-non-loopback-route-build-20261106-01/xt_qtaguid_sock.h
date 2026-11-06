/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_XT_QTAGUID_SOCK_H
#define _UAPI_XT_QTAGUID_SOCK_H

#include <linux/ioctl.h>

/* Private, opt-in gta3xlwifi ABI. No argument, same command on 32/64 bit.
 * Requires initial-namespace root plus CAP_NET_ADMIN and an empty own session.
 * New/retagged sockets then own their tags until explicit untag, UID deletion
 * or inet_release, not until the tagging daemon's process/session exits.
 * This does not authorize a caller or implement accounting budgets/readiness.
 */
#define QTAGUID_SOCKET_OWNED_SESSION _IO('q', 0x51)

#endif
