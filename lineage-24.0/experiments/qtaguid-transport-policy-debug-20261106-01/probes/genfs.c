
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb/services.h>
int main(int argc,char **argv){
 assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);assert(fseek(f,0,SEEK_END)==0);long n=ftell(f);assert(n>0);rewind(f);void *data=malloc(n);assert(data);assert(fread(data,1,n,f)==(size_t)n);assert(fclose(f)==0);assert(sepol_load_policy(data,n)==0);free(data);
 const char *paths[]={"/devices/virtual/misc/xt_qtaguid/dev","/module/xt_qtaguid/parameters/passive","/module/xt_qtaguid/parameters/tag_tracking_passive"};
 sepol_security_class_t c;assert(sepol_string_to_security_class("file",&c)==0);
 for(unsigned i=0;i<sizeof(paths)/sizeof(paths[0]);i++){sepol_security_id_t sid;sepol_security_context_t context;size_t size;assert(sepol_genfs_sid("sysfs",paths[i],c,&sid)==0);assert(sepol_sid_to_context(sid,&context,&size)==0);assert(!strcmp(context,"u:object_r:sysfs_gta3xlwifi_qtaguid:s0"));printf("genfs=%s context=%s\n",paths[i],context);free(context);}
 return 0;
}
