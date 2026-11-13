
#include <assert.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdlib.h>
#include <unistd.h>
#include <xtables.h>
static jmp_buf failure;static unsigned registrations,cases;
static struct xtables_match*matches[2];
void xtables_register_match(struct xtables_match*m){assert(registrations<2);matches[registrations++]=m;}
void xtables_error(unsigned code,const char*format,...){assert(code==PARAMETER_PROBLEM&&format);longjmp(failure,1);}
void xtables_option_parse(struct xt_option_call*c){if(c->invert)xtables_error(PARAMETER_PROBLEM,"inverted option");c->xflags|=1u<<c->entry->id;}
#define _init bad_iif_registration
#include "/srv/android/ports/lineage-24.0-arm64/xtables-ingress24-20261113-01/extensions/libxt_gta3xlwifi_bad_iif.c"
#undef _init
#define _init discard_registration
#include "/srv/android/ports/lineage-24.0-arm64/xtables-ingress24-20261113-01/extensions/libxt_gta3xlwifi_ingress_discard.c"
#undef _init

#define T(x) do{assert(x);++cases;}while(0)
static bool parse(struct xtables_match*m,struct xt_entry_match*frame,unsigned id,const char*value,bool invert){struct xt_option_call c={value,&m->x6_options[id],frame->data,0,invert};if(setjmp(failure))return false;m->x6_parse(&c);return true;}
static void save(struct xtables_match*m,struct xt_entry_match*frame,char*text,size_t size){fflush(stdout);int old=dup(1);assert(old>=0);FILE*t=tmpfile();assert(t&&dup2(fileno(t),1)>=0);m->save(NULL,frame);fflush(stdout);assert(dup2(old,1)>=0);close(old);rewind(t);size_t n=fread(text,1,size-1,t);text[n]=0;fclose(t);}
int main(void){
 bad_iif_registration();discard_registration();T(registrations==2&&matches[0]->size==8&&matches[1]->size==32);T(!strcmp(matches[0]->name,GTA3XLWIFI_BAD_IIF_MATCH)&&!strcmp(matches[1]->name,GTA3XLWIFI_INGRESS_DISCARD_MATCH));
 _Alignas(8) struct xt_entry_match frame;char text[200];
 for(unsigned m=0;m<2;m++){memset(&frame,0xff,sizeof(frame));matches[m]->init(&frame);for(unsigned i=0;i<(m?28:8);i++)assert(!frame.data[i]);T(matches[m]->family==NFPROTO_UNSPEC&&matches[m]->revision==0);for(unsigned i=0;i<(m?3:1);i++)T(matches[m]->x6_options[i].flags==XTOPT_MAND);}
 const char*valid[]={"0","1","17","2147483647","00017"};const unsigned wanted[]={0,1,17,2147483647,17};
 for(unsigned i=0;i<5;i++){
  matches[0]->init(&frame);T(parse(matches[0],&frame,0,valid[i],false));const struct gta3xlwifi_bad_iif_match*b=(const void*)frame.data;T(b->allowed_ifindex==wanted[i]&&!b->reserved);save(matches[0],&frame,text,sizeof(text));char expected[100];snprintf(expected,sizeof(expected)," --allowed-iif %u",wanted[i]);T(!strcmp(text,expected));
  for(unsigned id=1;id<3;id++){matches[1]->init(&frame);T(parse(matches[1],&frame,id,valid[i],false));const struct gta3xlwifi_ingress_discard_match*d=(const void*)frame.data;T(d->allowed_ifindex[id-1]==wanted[i]&&!d->reserved);}
 }
 const char*invalid[]={"","-1","+1","0x10"," 1","1 ","1x","2147483648","4294967295","99999999999999999999999"};
 for(unsigned m=0;m<2;m++)for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++){matches[m]->init(&frame);unsigned char old[64];memcpy(old,frame.data,64);T(!parse(matches[m],&frame,m?1:0,invalid[i],false)&&!memcmp(old,frame.data,64));}
 for(unsigned m=0;m<2;m++){matches[m]->init(&frame);T(!parse(matches[m],&frame,m?1:0,"17",true));}
 matches[1]->init(&frame);T(parse(matches[1],&frame,0,"00000000000000000000ffffc0a80102",false));T(parse(matches[1],&frame,1,"17",false));T(parse(matches[1],&frame,2,"2147483647",false));save(matches[1],&frame,text,sizeof(text));T(!strcmp(text," --ingress-daddr 00000000000000000000ffffc0a80102 --allowed-iif1 17 --allowed-iif2 2147483647"));
 for(const char**p=(const char*[]){"","::1","00000000000000000000000000000000","00000000000000000000ffff00000000","0000000000000000000000000000000A","0000000000000000000000000000000g","000000000000000000000000000000001",NULL};*p;p++){unsigned char old[64];memcpy(old,frame.data,64);T(!parse(matches[1],&frame,0,*p,false)&&!memcmp(old,frame.data,64));}
 printf("passed_cases=%u\n",cases);
}
