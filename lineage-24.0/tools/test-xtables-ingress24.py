#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual ingress xtables callback parsers/savers with a minimal API fixture.

Tests bounded numeric/hex inputs, no partial payload writes on error, ABI sizes,
registration metadata and canonical save output. Mandatory-option/inversion
engine behavior, actual CLI parsing and kernel execution are not claimed.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
(O/'xtables.h').write_text('''#pragma once
#include <stdbool.h>
#include <stddef.h>
#define NFPROTO_UNSPEC 0
#define XTABLES_VERSION "fixture"
#define XT_ALIGN(x) (((x)+7)&~7)
#define XTTYPE_STRING 1
#define XTOPT_MAND 1
#define XTOPT_TABLEEND {0}
#define PARAMETER_PROBLEM 2
struct xt_entry_match{unsigned char data[64];};
struct xt_option_entry{const char*name;unsigned id,type,flags;};
struct xt_option_call{const char*arg;const struct xt_option_entry*entry;void*data;unsigned xflags;bool invert;};
struct xtables_match{unsigned family;const char*name;unsigned revision;const char*version;size_t size,userspacesize;void(*help)(void);void(*init)(struct xt_entry_match*);void(*print)(const void*,const struct xt_entry_match*,int);void(*save)(const void*,const struct xt_entry_match*);void(*x6_parse)(struct xt_option_call*);const struct xt_option_entry*x6_options;};
void xtables_option_parse(struct xt_option_call*);
__attribute__((noreturn,format(printf,2,3))) void xtables_error(unsigned,const char*,...);
void xtables_register_match(struct xtables_match*);
''')
code=r'''
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
'''+ '#include "'+str(S/'extensions/libxt_gta3xlwifi_bad_iif.c')+'"\n#undef _init\n#define _init discard_registration\n#include "'+str(S/'extensions/libxt_gta3xlwifi_ingress_discard.c')+'"\n#undef _init\n'+r'''
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
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O),'-I'+str(S/'include'),str(O/'test.c'),'-o',str(O/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=30,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
match=re.fullmatch(r'passed_cases=(\d+)\n',r.stdout);assert match and int(match[1])>=70
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),S/'extensions/libxt_gta3xlwifi_bad_iif.c',S/'extensions/libxt_gta3xlwifi_ingress_discard.c',S/'include/linux/netfilter/gta3xlwifi_ingress.h',O/'test.c',O/'xtables.h'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip())
