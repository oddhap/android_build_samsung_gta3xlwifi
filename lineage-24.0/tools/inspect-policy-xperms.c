/* SPDX-License-Identifier: Apache-2.0
 * Read-only binary-policy inspection using the source-locked Android libsepol.
 * Host analysis, NOT a kernel loader/SELinux enforcement or approval test.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/polcaps.h>

static void inspect(const policydb_t *p, const avtab_t *table, const char *name,
                    uint64_t counts[256], unsigned *samples, int *comma) {
    for (uint32_t i = 0; i < table->nslot; ++i) {
        for (avtab_ptr_t n = table->htable[i]; n; n = n->next) {
            if (!(n->key.specified & AVTAB_XPERMS)) continue;
            const avtab_extended_perms_t *x = n->datum.xperms;
            if (!x) { fputs("Missing xperm payload\n", stderr); exit(2); }
            ++counts[x->specified];
            if (x->specified != AVTAB_XPERMS_NLMSG || *samples >= 8) continue;
            /* Type/class names are compiler-validated policy identifiers. */
            printf("%s{\"table\":\"%s\",\"source_type\":%u,\"target_type\":%u,"
                   "\"target_class\":%u,\"key_specified\":%u,\"xperm_specified\":%u,"
                   "\"driver\":%u,\"source_name\":\"%s\",\"target_name\":\"%s\","
                   "\"class_name\":\"%s\",\"perms\":[",
                   *comma ? "," : "", name, n->key.source_type, n->key.target_type,
                   n->key.target_class, n->key.specified, x->specified, x->driver,
                   p->p_type_val_to_name[n->key.source_type - 1],
                   p->p_type_val_to_name[n->key.target_type - 1],
                   p->p_class_val_to_name[n->key.target_class - 1]);
            for (unsigned j = 0; j < 8; ++j) printf("%s%" PRIu32, j ? "," : "", x->perms[j]);
            printf("]}");
            *comma = 1;
            ++*samples;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "Usage: %s POLICY_BINARY\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("policy input"); return 2; }
    sepol_policydb_t *db = NULL;
    sepol_policy_file_t *pf = NULL;
    if (sepol_policydb_create(&db) || sepol_policy_file_create(&pf)) return 2;
    sepol_policy_file_set_fp(pf, f);
    int rc = sepol_policydb_read(db, pf);
    fclose(f);
    if (rc) { fputs("Source-locked libsepol rejected binary policy\n", stderr); return 2; }
    uint64_t counts[256] = {0};
    unsigned samples = 0;
    int comma = 0;
    printf("{\"policy_binary_version\":%u,\"type_count\":%u,\"class_count\":%u,"
           "\"nlmsg_samples\":[", db->p.policyvers, db->p.p_types.nprim, db->p.p_classes.nprim);
    inspect(&db->p, &db->p.te_avtab, "unconditional", counts, &samples, &comma);
    inspect(&db->p, &db->p.te_cond_avtab, "conditional", counts, &samples, &comma);
    printf("],\"xperm_kind_counts\":{");
    comma = 0;
    for (unsigned i = 0; i < 256; ++i) {
        if (counts[i]) { printf("%s\"%u\":%" PRIu64, comma ? "," : "", i, counts[i]); comma = 1; }
    }
    printf("},\"netlink_xperm_enabled\":%s,\"enabled_policy_capabilities\":[",
           ebitmap_get_bit(&db->p.policycaps, POLICYDB_CAP_NETLINK_XPERM) ? "true" : "false");
    comma = 0;
    for (unsigned bit = 0; bit < db->p.policycaps.highbit; ++bit) {
        if (!ebitmap_get_bit(&db->p.policycaps, bit)) continue;
        const char *name = sepol_polcap_getname(bit);
        printf("%s{\"bit\":%u,\"name\":\"%s\"}", comma ? "," : "", bit, name ? name : "UNKNOWN");
        comma = 1;
    }
    printf("],\"actual_kernel_execution\":false}\n");
    sepol_policy_file_free(pf);
    sepol_policydb_free(db);
    return ferror(stdout) ? 2 : 0;
}
