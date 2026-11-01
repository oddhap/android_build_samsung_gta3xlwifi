/* SPDX-License-Identifier: Apache-2.0
 * Read-only, source-locked libsepol inspection of unconditional TE rules.
 * NOT full effective permissions: constraints, conditional state, kernel/runtime
 * and endpoint availability are not evaluated. No policy or image is modified.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>

static type_datum_t *type(const policydb_t *p, const char *name) {
    return hashtab_search(p->p_types.table, name);
}

static uint32_t unconditional_av(policydb_t *p, uint32_t source, uint32_t target,
                                 uint16_t tclass) {
    uint32_t allowed = 0;
    ebitmap_node_t *snode, *tnode;
    unsigned sbit, tbit;
    ebitmap_for_each_positive_bit(&p->type_attr_map[source - 1], snode, sbit) {
        ebitmap_for_each_positive_bit(&p->type_attr_map[target - 1], tnode, tbit) {
            avtab_key_t key = {.source_type = sbit + 1, .target_type = tbit + 1,
                               .target_class = tclass, .specified = AVTAB_ALLOWED};
            avtab_datum_t *datum = avtab_search(&p->te_avtab, &key);
            if (datum) allowed |= datum->data;
        }
    }
    return allowed;
}

int main(int argc, char **argv) {
    if (argc != 2 && !(argc == 3 && !strcmp(argv[2], "--all-domains"))) return 2;
    int all_domains = argc == 3;
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("policy"); return 2; }
    sepol_policydb_t *db = NULL;
    sepol_policy_file_t *pf = NULL;
    if (sepol_policydb_create(&db) || sepol_policy_file_create(&pf)) return 2;
    sepol_policy_file_set_fp(pf, f);
    int rc = sepol_policydb_read(db, pf);
    fclose(f);
    if (rc) return 2;
    policydb_t *p = &db->p;
    class_datum_t *cl = hashtab_search(p->p_classes.table, "service_manager");
    if (!cl) return 2;
    perm_datum_t *add = hashtab_search(cl->permissions.table, "add");
    perm_datum_t *find = hashtab_search(cl->permissions.table, "find");
    if (!add || !find || !add->s.value || !find->s.value ||
        add->s.value > 32 || find->s.value > 32) return 2;
    const char *sources[] = {"platform_app", "system_server", "untrusted_app"};
    const char *targets[] = {"uwb_service", "hal_uwb_service",
                            "vendor_samsung_legacy_uwb_service",
                            "vendor_samsung_legacy_hal_uwb_service"};
    int comma = 0;
    printf("{\"unconditional_te_only\":true,\"full_effective_access_or_runtime_proven\":false,\"queries\":[");
    type_datum_t *domain = type(p, "domain");
    if (!domain) return 2;
    unsigned limit = all_domains ? p->p_types.nprim : sizeof(sources)/sizeof(sources[0]);
    for (unsigned i = 0; i < limit; ++i) {
        const char *source_name;
        type_datum_t *s;
        if (all_domains) {
            s = p->type_val_to_struct[i];
            if (!s || s->flavor != TYPE_TYPE ||
                !ebitmap_get_bit(&p->type_attr_map[i], domain->s.value - 1)) continue;
            source_name = p->p_type_val_to_name[i];
        } else {
            source_name = sources[i];
            s = type(p, source_name);
        }
        if (!s || !source_name) return 2;
        for (unsigned j = 0; j < sizeof(targets)/sizeof(targets[0]); ++j) {
            type_datum_t *t = type(p, targets[j]);
            uint32_t av = t ? unconditional_av(p, s->s.value, t->s.value, cl->s.value) : 0;
            printf("%s{\"source\":\"%s\",\"target\":\"%s\",\"target_exists\":%s,"
                   "\"add\":%s,\"find\":%s}", comma ? "," : "", source_name, targets[j],
                   t ? "true" : "false", av & (1U << (add->s.value - 1)) ? "true" : "false",
                   av & (1U << (find->s.value - 1)) ? "true" : "false");
            comma = 1;
        }
    }
    printf("]}\n");
    sepol_policy_file_free(pf);
    sepol_policydb_free(db);
    return ferror(stdout) ? 2 : 0;
}
