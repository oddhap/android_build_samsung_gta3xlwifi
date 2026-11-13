/* SPDX-License-Identifier: GPL-2.0 */
/* Independent actual LNA predicate; no rule installation or readiness claim. */
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/gta3xlwifi_local_network.h>

static void lna_help(void)
{
	printf("gta3xlwifi_lna: actual shared A17 local-network denial; no options\n");
}

static void lna_init(struct xt_entry_match *match)
{
	memset(match->data, 0, sizeof(struct gta3xlwifi_lna_match));
}

static void lna_print(const void *ip, const struct xt_entry_match *match,
			int numeric)
{
	printf(" gta3xlwifi_lna");
}

static struct xtables_match lna_match = {
	.family = NFPROTO_UNSPEC,
	.name = GTA3XLWIFI_LNA_MATCH,
	.revision = 0,
	.version = XTABLES_VERSION,
	.size = XT_ALIGN(sizeof(struct gta3xlwifi_lna_match)),
	.userspacesize = XT_ALIGN(sizeof(struct gta3xlwifi_lna_match)),
	.help = lna_help,
	.init = lna_init,
	.print = lna_print,
};

void libxt_gta3xlwifi_lna_init(void)
{
	xtables_register_match(&lna_match);
}
