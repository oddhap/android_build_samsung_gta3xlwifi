/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/gta3xlwifi_ingress.h>
static const struct xt_option_entry bad_iif_options[] = {
    { .name = "allowed-iif", .id = 0, .type = XTTYPE_STRING, .flags = XTOPT_MAND },
    XTOPT_TABLEEND,
};
static unsigned bad_iif_index(const char *text)
{
    unsigned n = 0;
    if (!*text) xtables_error(PARAMETER_PROBLEM, "empty allowed interface index");
    for (; *text; ++text) {
        if (*text < '0' || *text > '9' || n > (INT_MAX - (unsigned)(*text - '0')) / 10)
            xtables_error(PARAMETER_PROBLEM, "invalid numeric interface index");
        n = n * 10 + *text - '0';
    }
    return n;
}
static void bad_iif_help(void)
{
    printf("gta3xlwifi_bad_iif: --allowed-iif INDEX (0: block all non-DNS/non-loopback ingress)\n");
}
static void bad_iif_init(struct xt_entry_match *match)
{
    memset(match->data, 0, sizeof(struct gta3xlwifi_bad_iif_match));
}
static void bad_iif_parse(struct xt_option_call *cb)
{
    struct gta3xlwifi_bad_iif_match *info = cb->data;
    xtables_option_parse(cb);
    info->allowed_ifindex = bad_iif_index(cb->arg);
}
static void bad_iif_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
    const struct gta3xlwifi_bad_iif_match *info = (const void *)match->data;
    printf(" allowed-iif %u", info->allowed_ifindex);
}
static void bad_iif_save(const void *ip, const struct xt_entry_match *match)
{
    const struct gta3xlwifi_bad_iif_match *info = (const void *)match->data;
    printf(" --allowed-iif %u", info->allowed_ifindex);
}
static struct xtables_match bad_iif_match = {
    .family = NFPROTO_UNSPEC, .name = GTA3XLWIFI_BAD_IIF_MATCH, .revision = 0,
    .version = XTABLES_VERSION, .size = XT_ALIGN(sizeof(struct gta3xlwifi_bad_iif_match)),
    .userspacesize = XT_ALIGN(sizeof(struct gta3xlwifi_bad_iif_match)),
    .help = bad_iif_help, .init = bad_iif_init, .print = bad_iif_print, .save = bad_iif_save,
    .x6_parse = bad_iif_parse, .x6_options = bad_iif_options,
};
void libxt_gta3xlwifi_bad_iif_init(void) { xtables_register_match(&bad_iif_match); }
