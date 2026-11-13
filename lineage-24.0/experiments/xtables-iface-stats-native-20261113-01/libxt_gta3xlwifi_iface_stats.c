/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
static const struct xt_option_entry iface_stats_options[] = {
    { .name = "direction", .id = 0, .type = XTTYPE_STRING, .flags = XTOPT_MAND },
    XTOPT_TABLEEND,
};
static void iface_stats_help(void)
{
    printf("gta3xlwifi_iface_stats: --direction ingress|egress (real interface counters)\n");
}
static void iface_stats_init(struct xt_entry_match *match)
{
    memset(match->data, 0, sizeof(struct gta3xlwifi_iface_stats_match));
}
static void iface_stats_parse(struct xt_option_call *cb)
{
    struct gta3xlwifi_iface_stats_match *info = cb->data;
    unsigned output;
    xtables_option_parse(cb);
    if (!strcmp(cb->arg, "ingress")) output = 0;
    else if (!strcmp(cb->arg, "egress")) output = 1;
    else xtables_error(PARAMETER_PROBLEM, "direction must be ingress or egress");
    info->output = output;
}
static void iface_stats_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
    const struct gta3xlwifi_iface_stats_match *info = (const void *)match->data;
    printf(" iface-stats %s", info->output ? "egress" : "ingress");
}
static void iface_stats_save(const void *ip, const struct xt_entry_match *match)
{
    const struct gta3xlwifi_iface_stats_match *info = (const void *)match->data;
    printf(" --direction %s", info->output ? "egress" : "ingress");
}
static struct xtables_match iface_stats_match = {
    .family = NFPROTO_UNSPEC, .name = GTA3XLWIFI_IFACE_STATS_MATCH, .revision = 0,
    .version = XTABLES_VERSION, .size = XT_ALIGN(sizeof(struct gta3xlwifi_iface_stats_match)),
    .userspacesize = XT_ALIGN(sizeof(struct gta3xlwifi_iface_stats_match)),
    .help = iface_stats_help, .init = iface_stats_init,
    .print = iface_stats_print, .save = iface_stats_save,
    .x6_parse = iface_stats_parse, .x6_options = iface_stats_options,
};
void libxt_gta3xlwifi_iface_stats_init(void) { xtables_register_match(&iface_stats_match); }
