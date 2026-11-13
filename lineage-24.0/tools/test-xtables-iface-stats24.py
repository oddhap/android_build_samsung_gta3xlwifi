#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual interface-counter XT callbacks with a bound API fixture.

The fixture tests payload, parser/saver and registration contracts, not actual
CLI option-engine behavior, rule installation or kernel accounting readiness.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();report=json.loads((R/'report.json').read_text());assert report['passed'] and report['passed_cases']==76
assert sha(R/'xtables.h')==report['inputs_sha256'][str(R/'xtables.h')];shutil.copyfile(R/'xtables.h',O/'xtables.h')
code=r'''
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
'''+ '#include "'+str(S/'extensions/libxt_gta3xlwifi_iface_stats.c')+'"\n#undef _init\n'+r'''
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
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O),'-I'+str(S/'include'),str(O/'test.c'),'-o',str(O/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=30,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',r.stdout);assert m and int(m[1])>=20
paths=[Path(__file__),R/'report.json',R/'xtables.h',S/'extensions/libxt_gta3xlwifi_iface_stats.c',S/'include/linux/netfilter/gta3xlwifi_iface_stats.h',O/'test.c',O/'xtables.h']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip())
