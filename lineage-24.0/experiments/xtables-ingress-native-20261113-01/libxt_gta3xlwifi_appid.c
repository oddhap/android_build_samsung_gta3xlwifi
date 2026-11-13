/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/gta3xlwifi_appid.h>

enum { O_APPID = 0 };
static const struct xt_option_entry appid_options[] = {
	{ .name = "appid", .id = O_APPID, .type = XTTYPE_UINT32RC,
	  .min = 0, .max = GTA3XLWIFI_APPID_USER_OFFSET - 1,
	  .flags = XTOPT_MAND },
	XTOPT_TABLEEND,
};
static void appid_help(void)
{
	printf("gta3xlwifi_appid: --appid value[:value] (0 through 99999)\n");
}
static void appid_parse(struct xt_option_call *cb)
{
	struct gta3xlwifi_appid_match *info = cb->data;
	xtables_option_parse(cb);
	info->minimum = cb->val.u32_range[0];
	info->maximum = cb->val.u32_range[cb->nvals >= 2 ? 1 : 0];
}
static void appid_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct gta3xlwifi_appid_match *info = (const void *)match->data;
	printf(" appid %u:%u", info->minimum, info->maximum);
}
static void appid_save(const void *ip, const struct xt_entry_match *match)
{
	const struct gta3xlwifi_appid_match *info = (const void *)match->data;
	printf(" --appid %u:%u", info->minimum, info->maximum);
}
static struct xtables_match appid_match = {
	.family = NFPROTO_UNSPEC,
	.name = GTA3XLWIFI_APPID_MATCH,
	.revision = 0,
	.version = XTABLES_VERSION,
	.size = XT_ALIGN(sizeof(struct gta3xlwifi_appid_match)),
	.userspacesize = XT_ALIGN(sizeof(struct gta3xlwifi_appid_match)),
	.help = appid_help,
	.print = appid_print,
	.save = appid_save,
	.x6_parse = appid_parse,
	.x6_options = appid_options,
};
void libxt_gta3xlwifi_appid_init(void)
{
	xtables_register_match(&appid_match);
}
