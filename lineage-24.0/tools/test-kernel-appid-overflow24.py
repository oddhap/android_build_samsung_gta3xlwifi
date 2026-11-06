#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare the actual private appId match with the Android17 system-UID predicate.

Actual C bodies run with fatal UBSan. Socket references/lookup, namespace and
registration are fixtures; no real kernel packets, rules or devices are tested.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=S/'net/netfilter/xt_qtaguid.c';text=source.read_text();header=S/'include/uapi/linux/netfilter/gta3xlwifi_appid.h';upstream=A/'packages/modules/Connectivity/bpf/progs/netd.h';uid_header=A/'system/core/libcutils/include/private/android_filesystem_config.h';stats=A/'packages/modules/Connectivity/bpf/progs/netd.c'
assert re.search(r'#define AID_USER_OFFSET\s+100000\b',uid_header.read_text()) and re.search(r'#define AID_APP_START\s+10000\b',uid_header.read_text())
assert 'if (sock_uid == 65534) sock_uid = 0;' in stats.read_text()
exported=O/'include/linux/netfilter/gta3xlwifi_appid.h';exported.parent.mkdir(parents=True);exported.write_bytes(header.read_bytes())
metadata=text[text.index('static struct xt_match gta3xlwifi_appid_reg'):text.index('static int __init gta3xlwifi_appid_init')]
prefix=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/netfilter/gta3xlwifi_appid.h>
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define TCP_TIME_WAIT 6
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NFPROTO_UNSPEC 0
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
typedef uint32_t uid_t;
struct user_namespace{int id;};static struct user_namespace init_user_ns,other_ns;static int overflowuid=65534;static struct user_namespace* ns=&init_user_ns;
static struct user_namespace* current_user_ns(void){return ns;}
struct sock{int sk_state,refs;uid_t sk_uid;};
struct sk_buff{struct sock* sk;};struct xt_action_param{const void* matchinfo;};struct xt_mtchk_param{const void* matchinfo;unsigned family;};
static struct sock* found;static unsigned put_count,lookups;
static struct sock* skb_to_full_sk(const struct sk_buff* skb){return skb->sk;}
static struct sock* qtaguid_find_sk(const struct sk_buff* skb,struct xt_action_param* par){(void)skb;(void)par;++lookups;if(found)++found->refs;return found;}
static uid_t from_kuid_munged(struct user_namespace* n,uid_t uid){assert(n==&init_user_ns);return uid==UINT32_MAX?(uid_t)overflowuid:uid;}
static void sock_gen_put(struct sock* sk){assert(sk&&sk->refs>0);--sk->refs;++put_count;}
struct xt_match{const char* name;unsigned revision,family,hooks,matchsize;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);void* me;};
static int register_result;static unsigned registers;
static int xt_register_match(struct xt_match* m){assert(m->revision==0&&m->family==0);++registers;return register_result;}
'''
code=prefix+m.extract(upstream.read_text(),'is_system_uid')+'\n'+m.extract(text,'gta3xlwifi_appid_mt')+'\n'+m.extract(text,'gta3xlwifi_appid_check')+'\n'+metadata+m.extract(text,'gta3xlwifi_appid_init')+r'''
static unsigned cases,comparisons;
#define C(x) do{assert(x);++cases;}while(0)
int main(void){
 struct gta3xlwifi_appid_match info={0,9999};struct xt_action_param p={&info};struct xt_mtchk_param c={&info,NFPROTO_IPV4};
 C(gta3xlwifi_appid_check(&c)==0);c.family=NFPROTO_IPV6;C(gta3xlwifi_appid_check(&c)==0);c.family=0;C(gta3xlwifi_appid_check(&c)==-EINVAL);c.family=2;
 ns=&other_ns;C(gta3xlwifi_appid_check(&c)==-EINVAL);ns=&init_user_ns;
 info.minimum=100;info.maximum=99;C(gta3xlwifi_appid_check(&c)==-EINVAL);info.minimum=0;info.maximum=100000;C(gta3xlwifi_appid_check(&c)==-EINVAL);info.maximum=UINT32_MAX;C(gta3xlwifi_appid_check(&c)==-EINVAL);info.maximum=9999;
 C(gta3xlwifi_appid_mt(NULL,&p)==false);
 struct sock direct={0,0,100001},lookup={0,0,110001};struct sk_buff skb={&direct};found=&lookup;
 C(gta3xlwifi_appid_mt(&skb,&p)&&lookups==0&&put_count==0&&lookup.refs==0);
 skb.sk=NULL;C(!gta3xlwifi_appid_mt(&skb,&p)&&lookups==1&&put_count==1&&lookup.refs==0);
 lookup.sk_uid=100001;C(gta3xlwifi_appid_mt(&skb,&p)&&put_count==2&&lookup.refs==0);
 found=NULL;C(gta3xlwifi_appid_mt(&skb,&p)&&put_count==2);
 direct.sk_state=TCP_TIME_WAIT;skb.sk=&direct;C(gta3xlwifi_appid_mt(&skb,&p)&&lookups==4&&put_count==2);direct.sk_state=0;
 for(uint32_t user=0;user<42950;user++){
  const uint32_t appids[]={0,1,9998,9999,10000,10001,65534,99999};
  for(unsigned i=0;i<sizeof(appids)/sizeof(appids[0]);i++){
   uint64_t full=(uint64_t)user*100000+appids[i];if(full>=UINT32_MAX)continue;
   direct.sk_uid=(uint32_t)full;uint32_t normalized=direct.sk_uid==65534?0:direct.sk_uid;
   bool expected=is_system_uid(normalized);assert(gta3xlwifi_appid_mt(&skb,&p)==expected);++comparisons;
  }
 }
 direct.sk_uid=UINT32_MAX;C(gta3xlwifi_appid_mt(&skb,&p));
 overflowuid=20000;skb.sk=NULL;found=NULL;C(!gta3xlwifi_appid_mt(&skb,&p));skb.sk=&direct;direct.sk_uid=UINT32_MAX;C(!gta3xlwifi_appid_mt(&skb,&p));overflowuid=65534;
 info.minimum=42;info.maximum=43;direct.sk_uid=100042;C(gta3xlwifi_appid_mt(&skb,&p));direct.sk_uid=200043;C(gta3xlwifi_appid_mt(&skb,&p));direct.sk_uid=300044;C(!gta3xlwifi_appid_mt(&skb,&p));direct.sk_uid=100041;C(!gta3xlwifi_appid_mt(&skb,&p));
 C(strcmp(gta3xlwifi_appid_reg.name,"gta3xlwifi_appid")==0);
 C(gta3xlwifi_appid_reg.match==gta3xlwifi_appid_mt&&gta3xlwifi_appid_reg.checkentry==gta3xlwifi_appid_check&&gta3xlwifi_appid_reg.matchsize==8&&gta3xlwifi_appid_reg.hooks==((1<<1)|(1<<3)));
 register_result=-ENOMEM;C(gta3xlwifi_appid_init()==-ENOMEM&&registers==1);register_result=0;C(gta3xlwifi_appid_init()==0&&registers==2);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env);(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',r.stdout);assert match and int(match[1])>=20 and int(match[2])>340000
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,source,header,upstream,uid_header,stats,O/'test.c',exported]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_android17_predicate_comparisons':int(match[2]),'stderr':r.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; actual C match vs Android17 predicate, fatal UBSan')
