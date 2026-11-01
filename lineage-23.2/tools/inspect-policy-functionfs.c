/* SPDX-License-Identifier: Apache-2.0
 * Actual binary FunctionFS default label + unconditional TE, not full AVC/USB.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>

static int permission(policydb_t *p, const char *source, const char *target,
                      const char *class_name, const char *perm_name) {
    type_datum_t *s = hashtab_search(p->p_types.table, source);
    type_datum_t *t = hashtab_search(p->p_types.table, target);
    class_datum_t *c = hashtab_search(p->p_classes.table, class_name);
    if (!s || !t || !c) return -1;
    perm_datum_t *perm = hashtab_search(c->permissions.table, perm_name);
    if (!perm && c->comdatum) perm = hashtab_search(c->comdatum->permissions.table, perm_name);
    if (!perm || !perm->s.value || perm->s.value > 32) return -1;
    uint32_t av = 0;
    ebitmap_node_t *sn, *tn;
    unsigned si, ti;
    ebitmap_for_each_positive_bit(&p->type_attr_map[s->s.value - 1], sn, si) {
        ebitmap_for_each_positive_bit(&p->type_attr_map[t->s.value - 1], tn, ti) {
            avtab_key_t k = {.source_type = si + 1, .target_type = ti + 1,
                            .target_class = c->s.value, .specified = AVTAB_ALLOWED};
            avtab_datum_t *d = avtab_search(&p->te_avtab, &k);
            if (d) av |= d->data;
        }
    }
    return !!(av & (1U << (perm->s.value - 1)));
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
    const char *label = NULL;
    for (genfs_t *g = p->genfs; g; g = g->next) {
        if (strcmp(g->fstype, "functionfs")) continue;
        for (ocontext_t *o = g->head; o; o = o->next) {
            if (!strcmp(o->u.name, "/")) {
                if (label || !o->context[0].type || o->context[0].type > p->p_types.nprim) return 2;
                label = p->p_type_val_to_name[o->context[0].type - 1];
            }
        }
    }
    if (!label || strcmp(label, "functionfs")) return 2;
    const char *sources[] = {"init", "init", "usbaccessory_device", "untrusted_app"};
    const char *targets[] = {"functionfs", "usbaccessory_device", "functionfs", "functionfs"};
    const char *classes[] = {"file", "file", "filesystem", "file"};
    const char *perms[] = {"relabelfrom", "relabelto", "associate", "relabelfrom"};
    printf("{\"policy_version\":%u,\"functionfs_policycap_bit12\":%s,"
           "\"genfs_root_type\":\"%s\",\"unconditional_te_only\":true,"
           "\"kernel_usb_runtime_proven\":false,\"queries\":[",
           p->policyvers, ebitmap_get_bit(&p->policycaps, 12) ? "true" : "false", label);
    for (unsigned i = 0; i < 4; ++i) {
        int allow = permission(p, sources[i], targets[i], classes[i], perms[i]);
        if (allow < 0) return 2;
        printf("%s{\"source\":\"%s\",\"target\":\"%s\",\"class\":\"%s\","
               "\"permission\":\"%s\",\"te_allowed\":%s}", i ? "," : "", sources[i],
               targets[i], classes[i], perms[i], allow ? "true" : "false");
    }
    printf("]}\n");
    sepol_policy_file_free(pf);
    sepol_policydb_free(db);
    return ferror(stdout) ? 2 : 0;
}
