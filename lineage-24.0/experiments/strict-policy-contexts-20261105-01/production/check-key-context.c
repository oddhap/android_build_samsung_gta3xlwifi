#include <assert.h>
#include <stdio.h>
#include <sepol/context.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
int main(int argc,char **argv){
 assert(argc>=2 && argc%2==0);FILE *f=fopen(argv[1],"rb");assert(f);
 sepol_policydb_t *p;sepol_policy_file_t *pf;sepol_handle_t *h=sepol_handle_create();
 assert(h&&sepol_policydb_create(&p)==0&&sepol_policy_file_create(&pf)==0);
 sepol_policy_file_set_fp(pf,f);assert(sepol_policydb_read(p,pf)==0);
 for(int i=2;i<argc;i+=2){sepol_context_t *c;assert(sepol_context_from_string(h,argv[i+1],&c)==0);assert(sepol_context_check(h,p,c)==0);
 type_datum_t *a=hashtab_search(p->p.p_types.table,argv[i]);assert(a && a->flavor==TYPE_ATTRIB);
 type_datum_t *t=hashtab_search(p->p.p_types.table,(char*)sepol_context_get_type(c));assert(t && t->flavor==TYPE_TYPE);
 assert(ebitmap_get_bit(&p->p.type_attr_map[t->s.value-1],a->s.value-1));sepol_context_free(c);}
 sepol_policy_file_free(pf);sepol_policydb_free(p);sepol_handle_destroy(h);fclose(f);return 0;
}
