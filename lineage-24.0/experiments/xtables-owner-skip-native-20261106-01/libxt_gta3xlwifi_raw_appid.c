/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/gta3xlwifi_socket_uid.h>

enum { O_RANGE = 0 };
static const struct xt_option_entry raw_appid_options[] = {
	{ .name = "raw_appid", .id = O_RANGE, .type = XTTYPE_UINT32RC,
	  .min = 0, .max = 99999U,
	  .flags = XTOPT_MAND },
	XTOPT_TABLEEND,
};
static void raw_appid_help(void)
{
	printf("gta3xlwifi_raw_appid: --raw_appid value[:value] (0 through 99999)\n");
}
static void raw_appid_parse(struct xt_option_call *cb)
{
	struct gta3xlwifi_socket_uid_match *info = cb->data;
	xtables_option_parse(cb);
	info->minimum = cb->val.u32_range[0];
	info->maximum = cb->val.u32_range[cb->nvals >= 2 ? 1 : 0];
}
static void raw_appid_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct gta3xlwifi_socket_uid_match *info = (const void *)match->data;
	printf(" raw_appid %u:%u", info->minimum, info->maximum);
}
static void raw_appid_save(const void *ip, const struct xt_entry_match *match)
{
	const struct gta3xlwifi_socket_uid_match *info = (const void *)match->data;
	printf(" --raw_appid %u:%u", info->minimum, info->maximum);
}
static struct xtables_match raw_appid_match = {
	.family = NFPROTO_UNSPEC,
	.name = GTA3XLWIFI_RAW_APPID_MATCH,
	.revision = 0,
	.version = XTABLES_VERSION,
	.size = XT_ALIGN(sizeof(struct gta3xlwifi_socket_uid_match)),
	.userspacesize = XT_ALIGN(sizeof(struct gta3xlwifi_socket_uid_match)),
	.help = raw_appid_help,
	.print = raw_appid_print,
	.save = raw_appid_save,
	.x6_parse = raw_appid_parse,
	.x6_options = raw_appid_options,
};
void libxt_gta3xlwifi_raw_appid_init(void)
{
	xtables_register_match(&raw_appid_match);
}
