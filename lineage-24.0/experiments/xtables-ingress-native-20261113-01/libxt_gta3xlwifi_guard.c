/* SPDX-License-Identifier: GPL-2.0 */
/* Opt-in leased packet barrier; no rule installation or readiness claim. */
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/gta3xlwifi_netpolicy.h>

static void guard_help(void)
{
	printf("gta3xlwifi_guard: matches while the leased barrier is held; no options\n");
}

static void guard_init(struct xt_entry_match *match)
{
	memset(match->data, 0, sizeof(struct gta3xlwifi_netpolicy_match));
}

static void guard_print(const void *ip, const struct xt_entry_match *match,
			int numeric)
{
	printf(" gta3xlwifi_guard");
}

static struct xtables_match guard_match = {
	.family = NFPROTO_UNSPEC,
	.name = GTA3XLWIFI_NETPOLICY_MATCH,
	.revision = 0,
	.version = XTABLES_VERSION,
	.size = XT_ALIGN(sizeof(struct gta3xlwifi_netpolicy_match)),
	.userspacesize = XT_ALIGN(sizeof(struct gta3xlwifi_netpolicy_match)),
	.help = guard_help,
	.init = guard_init,
	.print = guard_print,
};

void libxt_gta3xlwifi_guard_init(void)
{
	xtables_register_match(&guard_match);
}
