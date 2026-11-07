/* SPDX-License-Identifier: GPL-2.0 */
/* Opt-in A17 ordinary-owner packet exemption; no rule installation or readiness claim. */
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/gta3xlwifi_owner_skip.h>

static void non_loopback_help(void)
{
	printf("gta3xlwifi_non_loopback: actual packet interface index differs from1; no options\n");
}

static void non_loopback_init(struct xt_entry_match *match)
{
	memset(match->data, 0, sizeof(struct gta3xlwifi_owner_skip_match));
}

static void non_loopback_print(const void *ip, const struct xt_entry_match *match,
			int numeric)
{
	printf(" gta3xlwifi_non_loopback");
}

static struct xtables_match non_loopback_match = {
	.family = NFPROTO_UNSPEC,
	.name = GTA3XLWIFI_NON_LOOPBACK_MATCH,
	.revision = 0,
	.version = XTABLES_VERSION,
	.size = XT_ALIGN(sizeof(struct gta3xlwifi_owner_skip_match)),
	.userspacesize = XT_ALIGN(sizeof(struct gta3xlwifi_owner_skip_match)),
	.help = non_loopback_help,
	.init = non_loopback_init,
	.print = non_loopback_print,
};

void libxt_gta3xlwifi_non_loopback_init(void)
{
	xtables_register_match(&non_loopback_match);
}
