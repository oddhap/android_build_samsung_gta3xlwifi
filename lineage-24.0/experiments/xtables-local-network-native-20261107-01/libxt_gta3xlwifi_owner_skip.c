/* SPDX-License-Identifier: GPL-2.0 */
/* Opt-in A17 ordinary-owner packet exemption; no rule installation or readiness claim. */
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/gta3xlwifi_owner_skip.h>

static void owner_skip_help(void)
{
	printf("gta3xlwifi_owner_skip: ordinary ESP/RST/ingress FIN exemption; no options\n");
}

static void owner_skip_init(struct xt_entry_match *match)
{
	memset(match->data, 0, sizeof(struct gta3xlwifi_owner_skip_match));
}

static void owner_skip_print(const void *ip, const struct xt_entry_match *match,
			int numeric)
{
	printf(" gta3xlwifi_owner_skip");
}

static struct xtables_match owner_skip_match = {
	.family = NFPROTO_UNSPEC,
	.name = GTA3XLWIFI_OWNER_SKIP_MATCH,
	.revision = 0,
	.version = XTABLES_VERSION,
	.size = XT_ALIGN(sizeof(struct gta3xlwifi_owner_skip_match)),
	.userspacesize = XT_ALIGN(sizeof(struct gta3xlwifi_owner_skip_match)),
	.help = owner_skip_help,
	.init = owner_skip_init,
	.print = owner_skip_print,
};

void libxt_gta3xlwifi_owner_skip_init(void)
{
	xtables_register_match(&owner_skip_match);
}
