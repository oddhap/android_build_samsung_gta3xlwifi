/* SPDX-License-Identifier: GPL-2.0 */
/* Host driver; three actual MLS helper bodies are prepended by the runner. */
int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *f = fopen(argv[1], "rb");
    assert(f && !fseek(f, 0, SEEK_END));
    long length = ftell(f);
    assert(length > 0);
    rewind(f);
    char *data = malloc(length);
    assert(data && fread(data, 1, length, f) == (size_t)length);
    fclose(f);
    avtab_cache_init();
    struct policy_file pf = {data, (size_t)length};
    int rc = policydb_read(&policydb, &pf);
    printf("rc=%d consumed=%zu remaining=%zu types=%u classes=%u\n",
           rc, length - pf.len, pf.len, policydb.p_types.nprim,
           policydb.p_classes.nprim);
    if (!rc) {
        unsigned kinds[256] = {0};
        struct avtab *tables[] = {&policydb.te_avtab, &policydb.te_cond_avtab};
        for (unsigned t = 0; t < ARRAY_SIZE(tables); ++t) {
            for (unsigned i = 0; i < tables[t]->nslot; ++i) {
                struct avtab_node *node = flex_array_get_ptr(tables[t]->htable, i);
                for (; node; node = node->next)
                    if (node->key.specified & AVTAB_XPERMS)
                        kinds[node->datum.u.xperms->specified]++;
            }
        }
        printf("ioctl=%u nlmsg=%u\n", kinds[1], kinds[3]);
        policydb_destroy(&policydb);
    }
    free(data);
    avtab_cache_destroy();
    return 0;
}
