
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb/services.h>
int main(int argc,char **argv){
 assert(argc>2&&(argc-2)%4==0);FILE *f=fopen(argv[1],"rb");assert(f);assert(fseek(f,0,SEEK_END)==0);long n=ftell(f);assert(n>0);rewind(f);void *data=malloc(n);assert(data);assert(fread(data,1,n,f)==(size_t)n);assert(fclose(f)==0);assert(sepol_load_policy(data,n)==0);free(data);
 for(int i=2;i<argc;i+=4){
  sepol_security_id_t s,t;sepol_security_class_t c;sepol_access_vector_t permission;struct sepol_av_decision av;
  assert(sepol_context_to_sid(argv[i],strlen(argv[i])+1,&s)==0);
  assert(sepol_context_to_sid(argv[i+1],strlen(argv[i+1])+1,&t)==0);
  assert(sepol_string_to_security_class(argv[i+2],&c)==0);
  assert(sepol_string_to_av_perm(c,argv[i+3],&permission)==0);
  assert(sepol_compute_av(s,t,c,permission,&av)==0);
  printf("%d %u %u\n",(i-2)/4,(av.allowed&permission)==permission,av.flags);
 }
 return 0;
}
