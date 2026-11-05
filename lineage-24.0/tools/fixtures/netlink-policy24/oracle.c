/* Read-only independent Android17 libsepol oracle, not a kernel loader. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/sidtab.h>
typedef uint32_t u32;
struct security_class_mapping {const char *name;const char *perms[sizeof(u32)*8+1];};
#include "classmap.h"
static policydb_t *p;
static sidtab_t table;
static unsigned get_sid(const char *type,unsigned cat) {
    char context[512];
    int n=snprintf(context,sizeof(context),cat?"u:r:%s:s0:c%u":"u:r:%s:s0",type,cat?cat-1:0);assert(n>0 && (size_t)n<sizeof(context));
    sepol_security_id_t sid;assert(!sepol_context_to_sid(context,strlen(context)+1,&sid));return sid;
}
static void xperms(unsigned st,unsigned tt,unsigned cl,unsigned base,unsigned driver,unsigned *used,unsigned *bases,uint32_t vectors[3][8]) {
    ebitmap_node_t *sn,*tn;unsigned s,t;
    ebitmap_for_each_positive_bit(&p->type_attr_map[st-1],sn,s) {
        ebitmap_for_each_positive_bit(&p->type_attr_map[tt-1],tn,t) {
            avtab_key_t key={.source_type=s+1,.target_type=t+1,.target_class=cl,.specified=AVTAB_XPERMS};
            for(avtab_ptr_t node=avtab_search_node(&p->te_avtab,&key);node;node=avtab_search_node_next(node,AVTAB_XPERMS)) {
                avtab_extended_perms_t *x=node->datum.xperms;
                unsigned family=x->specified==AVTAB_XPERMS_NLMSG?2:1;assert(x->specified>=1 && x->specified<=3);*bases |= family;
                if(base!=family)continue;
                bool all=x->specified==AVTAB_XPERMS_IOCTLDRIVER;
                if(all?!(x->perms[driver/32]&(1U<<(driver%32))):x->driver!=driver)continue;
                unsigned kind=node->key.specified & ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);
                unsigned which=kind==AVTAB_XPERMS_ALLOWED?0:kind==AVTAB_XPERMS_AUDITALLOW?1:2;
                assert(kind==AVTAB_XPERMS_ALLOWED||kind==AVTAB_XPERMS_AUDITALLOW||kind==AVTAB_XPERMS_DONTAUDIT);
                *used |= 1U<<which;
                for(unsigned i=0;i<8;i++)vectors[which][i]|=all?UINT32_MAX:x->perms[i];
            }
        }
    }
}
static unsigned type_id(const char *name) {type_datum_t *t=hashtab_search(p->p_types.table,name);assert(t && t->flavor==TYPE_TYPE);return t->s.value;}
int main(int argc,char **argv) {
    assert(argc==3);FILE *f=fopen(argv[1],"rb");assert(f);sepol_policydb_t *db;sepol_policy_file_t *pf;assert(!sepol_policydb_create(&db)&&!sepol_policy_file_create(&pf));sepol_policy_file_set_fp(pf,f);assert(!sepol_policydb_read(db,pf));fclose(f);sepol_policy_file_free(pf);p=&db->p;
    assert(!p->p_bools.nprim && !p->te_cond_avtab.nel);
    assert(!sepol_sidtab_init(&table));assert(!sepol_set_policydb(p)&&!sepol_set_sidtab(&table));
    f=fopen(argv[2],"r");assert(f);unsigned id,scat,tcat,base,driver;char sn[256],tn[256],cl[256];
    while(fscanf(f,"%u %255s %255s %255s %u %u %u %u",&id,sn,tn,cl,&scat,&tcat,&base,&driver)==8) {
        unsigned s=get_sid(sn,scat),t=get_sid(tn,tcat);sepol_security_class_t pc;assert(!sepol_string_to_security_class(cl,&pc));
        struct sepol_av_decision av;assert(!sepol_compute_av(s,t,pc,UINT32_MAX,&av));
        struct security_class_mapping *map=secclass_map;while(map->name && strcmp(map->name,cl))map++;assert(map->name);
        uint32_t projection[3]={0};unsigned n=0;for(;map->perms[n];n++){sepol_access_vector_t bit;assert(!sepol_string_to_av_perm(pc,map->perms[n],&bit));if(av.allowed&bit)projection[0]|=1U<<n;if(av.auditallow&bit)projection[1]|=1U<<n;if(av.auditdeny&bit)projection[2]|=1U<<n;}
        for(unsigned i=n;i<32;i++)projection[2]|=1U<<i;
        unsigned used=0,bases=0;uint32_t vectors[3][8]={{0}};xperms(type_id(sn),type_id(tn),pc,base,driver,&used,&bases,vectors);
        printf("%u %u %u %u %u %u %u %u %u",id,av.allowed,av.auditallow,av.auditdeny,projection[0],projection[1],projection[2],used,bases);
        for(unsigned j=0;j<3;j++)for(unsigned k=0;k<8;k++)printf(" %u",vectors[j][k]);
        sepol_access_vector_t requested;assert(!sepol_string_to_av_perm(pc,base==1?"ioctl":"nlmsg",&requested));
        for(unsigned mode=0;mode<3;mode++)for(unsigned k=0;k<8;k++)printf(" %u",!(av.allowed&requested)?0:!bases?UINT32_MAX:(used&1)?vectors[0][k]:0);
        if(base==2)for(unsigned mode=0;mode<3;mode++)for(unsigned k=0;k<8;k++)printf(" %u",!(av.allowed&requested)?0:!bases?UINT32_MAX:(used&1)?vectors[0][k]:0);
        printf("\n");
    }
    assert(feof(f));fclose(f);sepol_sidtab_destroy(&table);sepol_policydb_free(db);return 0;
}
