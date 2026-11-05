#include <assert.h>
#include <stdio.h>
#include <sepol/context.h>
#include <sepol/policydb.h>

int main(int argc,char **argv){
 assert(argc>=2 && argc%2==0);FILE *f=fopen(argv[1],"rb");assert(f);
 sepol_policydb_t *p;sepol_policy_file_t *pf;sepol_handle_t *h=sepol_handle_create();
 assert(h&&sepol_policydb_create(&p)==0&&sepol_policy_file_create(&pf)==0);
 sepol_policy_file_set_fp(pf,f);assert(sepol_policydb_read(p,pf)==0);
 for(int i=2;i<argc;i+=2){sepol_context_t *c;assert(sepol_context_from_string(h,argv[i+1],&c)==0);assert(sepol_context_check(h,p,c)==0);
 sepol_context_free(c);}
 sepol_policy_file_free(pf);sepol_policydb_free(p);sepol_handle_destroy(h);fclose(f);return 0;
}
