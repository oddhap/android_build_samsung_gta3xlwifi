
#include <assert.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdlib.h>
#include <unistd.h>
#include <xtables.h>
static jmp_buf failure;static unsigned registrations,cases;
static struct xtables_match *match;
void xtables_register_match(struct xtables_match*m){assert(!registrations++);match=m;}
void xtables_error(unsigned code,const char*format,...){assert(code==PARAMETER_PROBLEM&&format);longjmp(failure,1);}
void xtables_option_parse(struct xt_option_call*c){if(c->invert)xtables_error(PARAMETER_PROBLEM,"inverted option");c->xflags|=1u<<c->entry->id;}
#define _init iface_registration
#include "/srv/android/ports/lineage-24.0-arm64/xtables-iface-stats24-20261113-01/extensions/libxt_gta3xlwifi_iface_stats.c"
#undef _init

#define T(x) do{assert(x);++cases;}while(0)
static bool parse(struct xt_entry_match*f,const char*v,bool invert){struct xt_option_call c={v,&match->x6_options[0],f->data,0,invert};if(setjmp(failure))return false;match->x6_parse(&c);return true;}
static void output(struct xt_entry_match*f,char*text,size_t size,bool print){fflush(stdout);int old=dup(1);assert(old>=0);FILE*t=tmpfile();assert(t&&dup2(fileno(t),1)>=0);if(print)match->print(NULL,f,0);else match->save(NULL,f);fflush(stdout);assert(dup2(old,1)>=0);close(old);rewind(t);size_t n=fread(text,1,size-1,t);text[n]=0;fclose(t);}
int main(void){
 iface_registration();T(registrations==1);T(!strcmp(match->name,GTA3XLWIFI_IFACE_STATS_MATCH));T(match->revision==0&&match->family==NFPROTO_UNSPEC);T(match->size==8&&match->userspacesize==8);T(!strcmp(match->x6_options[0].name,"direction")&&match->x6_options[0].flags==XTOPT_MAND&&match->x6_options[0].type==XTTYPE_STRING);
 _Alignas(8) struct xt_entry_match frame;char text[100];memset(&frame,0xff,sizeof(frame));match->init(&frame);T(!memcmp(frame.data,(unsigned char[8]){0},8));
 const char*directions[]={"ingress","egress"};for(unsigned i=0;i<2;++i){match->init(&frame);T(parse(&frame,directions[i],false));const struct gta3xlwifi_iface_stats_match*info=(const void*)frame.data;T(info->output==i&&!info->reserved);output(&frame,text,sizeof(text),false);char wanted[100];snprintf(wanted,sizeof(wanted)," --direction %s",directions[i]);T(!strcmp(text,wanted));output(&frame,text,sizeof(text),true);snprintf(wanted,sizeof(wanted)," iface-stats %s",directions[i]);T(!strcmp(text,wanted));}
 const char*invalid[]={"","in","out","Ingress","EGRESS"," ingress","ingress ","0","1"};for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);++i){unsigned char before[64];memcpy(before,frame.data,64);T(!parse(&frame,invalid[i],false)&&!memcmp(before,frame.data,64));}
 for(unsigned i=0;i<2;++i){unsigned char before[64];memcpy(before,frame.data,64);T(!parse(&frame,directions[i],true)&&!memcmp(before,frame.data,64));}
 printf("passed_cases=%u\n",cases);
}
