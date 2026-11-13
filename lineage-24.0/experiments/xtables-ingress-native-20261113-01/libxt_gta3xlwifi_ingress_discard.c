/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/gta3xlwifi_ingress.h>
static const struct xt_option_entry ingress_discard_options[] = {
    { .name = "ingress-daddr", .id = 0, .type = XTTYPE_STRING, .flags = XTOPT_MAND },
    { .name = "allowed-iif1", .id = 1, .type = XTTYPE_STRING, .flags = XTOPT_MAND },
    { .name = "allowed-iif2", .id = 2, .type = XTTYPE_STRING, .flags = XTOPT_MAND },
    XTOPT_TABLEEND,
};
static unsigned ingress_discard_index(const char *text)
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
static void ingress_discard_help(void)
{
    printf("gta3xlwifi_ingress_discard: --ingress-daddr HEX32 --allowed-iif1 INDEX --allowed-iif2 INDEX\n");
}
static void ingress_discard_init(struct xt_entry_match *match)
{
    memset(match->data, 0, sizeof(struct gta3xlwifi_ingress_discard_match));
}
static void ingress_discard_parse(struct xt_option_call *cb)
{
    struct gta3xlwifi_ingress_discard_match *info = cb->data;
    unsigned i;
    xtables_option_parse(cb);
    if (cb->entry->id == 1) info->allowed_ifindex[0] = ingress_discard_index(cb->arg);
    else if (cb->entry->id == 2) info->allowed_ifindex[1] = ingress_discard_index(cb->arg);
    else {
        unsigned char bytes[16] = {0};
        static const unsigned char zero[16];
        static const unsigned char mapped_zero[16] = {0,0,0,0,0,0,0,0,0,0,255,255,0,0,0,0};
        if (strlen(cb->arg) != 32)
            xtables_error(PARAMETER_PROBLEM, "destination must have 32 lowercase hex digits");
        for (i = 0; i < 32; ++i) {
            char c = cb->arg[i];
            unsigned v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else xtables_error(PARAMETER_PROBLEM, "invalid lowercase hex destination");
            bytes[i / 2] = (bytes[i / 2] << 4) | v;
        }
        if (!memcmp(bytes, zero, 16) || !memcmp(bytes, mapped_zero, 16))
            xtables_error(PARAMETER_PROBLEM, "unassigned destination cannot be protected");
        memcpy(info->daddr, bytes, sizeof(bytes));
    }
}
static void ingress_discard_save(const void *ip, const struct xt_entry_match *match)
{
    const struct gta3xlwifi_ingress_discard_match *info = (const void *)match->data;
    unsigned i;
    printf(" --ingress-daddr ");
    for (i = 0; i < 16; ++i) printf("%02x", info->daddr[i]);
    printf(" --allowed-iif1 %u --allowed-iif2 %u", info->allowed_ifindex[0], info->allowed_ifindex[1]);
}
static void ingress_discard_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
    ingress_discard_save(ip, match);
}
static struct xtables_match ingress_discard_match = {
    .family = NFPROTO_UNSPEC, .name = GTA3XLWIFI_INGRESS_DISCARD_MATCH, .revision = 0,
    .version = XTABLES_VERSION, .size = XT_ALIGN(sizeof(struct gta3xlwifi_ingress_discard_match)),
    .userspacesize = XT_ALIGN(sizeof(struct gta3xlwifi_ingress_discard_match)),
    .help = ingress_discard_help, .init = ingress_discard_init,
    .print = ingress_discard_print, .save = ingress_discard_save,
    .x6_parse = ingress_discard_parse, .x6_options = ingress_discard_options,
};
void libxt_gta3xlwifi_ingress_discard_init(void) { xtables_register_match(&ingress_discard_match); }
