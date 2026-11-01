/* SPDX-License-Identifier: Apache-2.0
 * Offline unconditional process2 TE inspection using source-locked libsepol.
 * NOT kernel AVC, constraints, complete exec authorization or runtime proof.
 */
#include <stdio.h>
#include <stdint.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>

static uint32_t allowed(policydb_t *p, uint32_t source, uint32_t target, uint16_t cls) {
    uint32_t av = 0;
    ebitmap_node_t *snode, *tnode;
    unsigned sbit, tbit;
    ebitmap_for_each_positive_bit(&p->type_attr_map[source - 1], snode, sbit) {
        ebitmap_for_each_positive_bit(&p->type_attr_map[target - 1], tnode, tbit) {
            avtab_key_t key = {.source_type = sbit + 1, .target_type = tbit + 1,
                              .target_class = cls, .specified = AVTAB_ALLOWED};
            avtab_datum_t *d = avtab_search(&p->te_avtab, &key);
            if (d) av |= d->data;
        }
    }
    return av;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    sepol_policydb_t *db = NULL;
    sepol_policy_file_t *pf = NULL;
    if (sepol_policydb_create(&db) || sepol_policy_file_create(&pf)) return 2;
    sepol_policy_file_set_fp(pf, f);
    int rc = sepol_policydb_read(db, pf);
    fclose(f);
    if (rc) return 2;
    policydb_t *p = &db->p;
    class_datum_t *cls = hashtab_search(p->p_classes.table, "process2");
    if (!cls) return 2;
    perm_datum_t *nnp = hashtab_search(cls->permissions.table, "nnp_transition");
    perm_datum_t *nosuid = hashtab_search(cls->permissions.table, "nosuid_transition");
    if (!nnp || !nosuid || !nnp->s.value || !nosuid->s.value ||
        nnp->s.value > 32 || nosuid->s.value > 32) return 2;
    const char *sources[] = {"kernel", "overlay_remounter", "platform_app"};
    const char *targets[] = {"overlay_remounter", "init", "init"};
    printf("{\"policy_version\":%u,\"nnp_nosuid_capability_bit5\":%s,"
           "\"unconditional_te_only\":true,\"kernel_runtime_proven\":false,\"queries\":[",
           p->policyvers, ebitmap_get_bit(&p->policycaps, 5) ? "true" : "false");
    for (unsigned i = 0; i < 3; ++i) {
        type_datum_t *s = hashtab_search(p->p_types.table, sources[i]);
        type_datum_t *t = hashtab_search(p->p_types.table, targets[i]);
        if (!s || !t) return 2;
        uint32_t av = allowed(p, s->s.value, t->s.value, cls->s.value);
        printf("%s{\"source\":\"%s\",\"target\":\"%s\",\"nnp_transition\":%s,"
               "\"nosuid_transition\":%s}", i ? "," : "", sources[i], targets[i],
               av & (1U << (nnp->s.value - 1)) ? "true" : "false",
               av & (1U << (nosuid->s.value - 1)) ? "true" : "false");
    }
    printf("]}\n");
    sepol_policy_file_free(pf);
    sepol_policydb_free(db);
    return ferror(stdout) ? 2 : 0;
}
