#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check actual raw socket UID/appId matches against Android17 metered predicates.

Real C bodies and A17 allow/deny expressions, fatal UBSan. Socket state/namespace,
Linux helper UID results, BPF map lookup and registration are fixtures; no packets,
real BPF/kernel/device execution or backend readiness is established.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=S/'net/netfilter/xt_qtaguid.c';text=source.read_text();header=S/'include/uapi/linux/netfilter/gta3xlwifi_socket_uid.h';reference=A/'packages/modules/Connectivity/bpf/progs/netd.c';enum_header=A/'packages/modules/Connectivity/bpf/progs/netd.h'
exported=O/'include/linux/netfilter/gta3xlwifi_socket_uid.h';exported.parent.mkdir(parents=True);exported.write_bytes(header.read_bytes())
appid_header=S/'include/uapi/linux/netfilter/gta3xlwifi_appid.h'
(O/'include/linux/netfilter/gta3xlwifi_appid.h').write_bytes(appid_header.read_bytes())
aids=A/'system/core/libcutils/include/private/android_filesystem_config.h';assert re.search(r'#define AID_USER_OFFSET\s+100000\b',aids.read_text()) and re.search(r'#define AID_APP_START\s+10000\b',aids.read_text())
functions=['gta3xlwifi_raw_socket_uid','gta3xlwifi_raw_uid_mt','gta3xlwifi_raw_appid_mt','gta3xlwifi_raw_uid_check','gta3xlwifi_raw_appid_check'];actual='\n'.join(m.extract(text,n) for n in functions);assert 'qtaguid_find_sk' not in actual
metadata=text[text.index('static struct xt_match gta3xlwifi_raw_uid_reg'):text.index('static int __init gta3xlwifi_raw_uid_init')]
enum=re.search(r'enum UidOwnerMatchType : uint32_t \{.*?\n\};',enum_header.read_text(),re.S).group().replace(' : uint32_t','')
r=reference.read_text()
for name in ['allowlist_xtbpf','denylist_xtbpf']:
 old='DEFINE_XTBPF_PROG(skfilter, '+name+')\n';assert r.count(old)==1;r=r.replace(old,'static int '+name)
oracles='\n'.join(m.extract(r,n) for n in ['allowlist_xtbpf','denylist_xtbpf'])
prefix=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/netfilter/gta3xlwifi_socket_uid.h>
#include <linux/netfilter/gta3xlwifi_appid.h>
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define NFPROTO_UNSPEC 0
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NF_INET_LOCAL_IN 1
#define NF_INET_FORWARD 2
#define NF_INET_LOCAL_OUT 3
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
#define XTBPF_MATCH 1
#define XTBPF_NOMATCH 0
typedef uint32_t uid_t;
struct user_namespace{uint32_t offset;};static struct user_namespace init_user_ns={0},other_ns={100000};static struct user_namespace* current_ns=&init_user_ns;
static struct user_namespace* current_user_ns(void){return current_ns;}
static int overflowuid=65534;
struct net{struct user_namespace* user_ns;};static struct net initial_net={&init_user_ns},other_net={&other_ns};
struct sock{bool full;uid_t sk_uid;struct net* net;};
struct sk_buff{struct sock* sk;};struct xt_action_param{const void* matchinfo;};struct xt_mtchk_param{const void* matchinfo;unsigned family;};
static struct sock* skb_to_full_sk(const struct sk_buff* skb){return skb->sk;}
static bool sk_fullsock(const struct sock* sk){return sk->full;}
static struct net* sock_net(const struct sock* sk){return sk->net;}
static uid_t sock_net_uid(const struct net* n,const struct sock* sk){assert(n==sk->net);return sk->sk_uid;}
static uid_t from_kuid_munged(const struct user_namespace* n,uid_t uid){if(uid==UINT32_MAX||uid<n->offset)return overflowuid;return uid-n->offset;}
struct xt_match{const char* name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void* me;};
static int register_result;static unsigned registers;
static int xt_register_matches(struct xt_match* matches,unsigned count){assert(count==2&&matches[0].matchsize==8&&matches[1].matchsize==8);++registers;return register_result;}
struct __sk_buff{uint32_t reference_uid;};
static uint32_t bpf_get_socket_uid(const struct __sk_buff* skb){return skb->reference_uid;}
typedef struct{uint32_t iif,rule;}UidOwnerValue;static UidOwnerValue entry;static uint32_t entry_uid;static bool present;
static UidOwnerValue* bpf_uid_owner_map_lookup_elem(const uint32_t* uid){return present&&*uid==entry_uid?&entry:NULL;}
'''
if 'gta3xlwifi_socket_context_uid(' in actual:
 prefix+='\ntypedef uint32_t u32;\nstatic bool gta3xlwifi_socket_context_uid(const struct sk_buff*s,u32*u){(void)s;(void)u;return false;} /* outside private evaluator regression */\n'
code=prefix+enum+'\n'+m.extract(enum_header.read_text(),'is_system_uid')+'\n'+actual+'\n'+metadata+m.extract(text,'gta3xlwifi_raw_uid_init')+'\n'+oracles+r'''
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
int main(void){
 struct gta3xlwifi_socket_uid_match uid={0,UINT32_MAX},core={0,9999};struct xt_action_param p={&uid},c={&core};struct xt_mtchk_param check={&uid,NFPROTO_IPV4};
 T(gta3xlwifi_raw_uid_check(&check)==0);check.family=NFPROTO_IPV6;T(gta3xlwifi_raw_uid_check(&check)==0);check.family=0;T(gta3xlwifi_raw_uid_check(&check)==-EINVAL);check.family=2;current_ns=&other_ns;T(gta3xlwifi_raw_uid_check(&check)==-EINVAL);current_ns=&init_user_ns;
 uid.minimum=100;uid.maximum=99;T(gta3xlwifi_raw_uid_check(&check)==-EINVAL);uid.minimum=0;uid.maximum=UINT32_MAX;T(gta3xlwifi_raw_appid_check(&check)==-EINVAL);check.matchinfo=&core;T(gta3xlwifi_raw_appid_check(&check)==0);check.matchinfo=&uid;
 T(!gta3xlwifi_raw_uid_mt(NULL,&p)&&!gta3xlwifi_raw_appid_mt(NULL,&c));
 struct sock sk={true,10001,&initial_net};struct sk_buff skb={&sk};
 T(gta3xlwifi_raw_socket_uid(&skb)==10001);sk.full=false;T(gta3xlwifi_raw_socket_uid(&skb)==65534);sk.full=true;sk.sk_uid=UINT32_MAX;T(gta3xlwifi_raw_socket_uid(&skb)==65534);sk.sk_uid=100001;sk.net=&other_net;T(gta3xlwifi_raw_socket_uid(&skb)==1);
 // Explicit absent socket: raw UID65534 remains selectable by the denylist,
 // while the core/appId allowlist view treats it as root. No slow lookup exists.
 skb.sk=NULL;uid.minimum=uid.maximum=65534;T(gta3xlwifi_raw_uid_mt(&skb,&p));T(gta3xlwifi_raw_appid_mt(&skb,&c));
 overflowuid=20000;uid.minimum=uid.maximum=20000;T(gta3xlwifi_raw_uid_mt(&skb,&p)&&!gta3xlwifi_raw_appid_mt(&skb,&c));overflowuid=65534;
 const uint32_t values[]={0,1,9999,10000,10001,65534,65535,99999,100001,109999,110001,UINT32_MAX};
 for(unsigned context=0;context<ARRAY_SIZE(values)+2;context++)for(unsigned alternate=0;alternate<2;alternate++)for(unsigned have=0;have<2;have++)for(unsigned bits=0;bits<8;bits++){
  uint32_t expected_raw;
  sk.net=&initial_net;sk.full=true;skb.sk=&sk;
  if(context<ARRAY_SIZE(values)){sk.sk_uid=values[context];expected_raw=sk.sk_uid==UINT32_MAX?65534:sk.sk_uid;}
  else if(context==ARRAY_SIZE(values)){skb.sk=NULL;expected_raw=65534;}
  else{sk.full=false;sk.sk_uid=10001;expected_raw=65534;}
  struct __sk_buff oracle={expected_raw};present=have;entry_uid=alternate?12345:expected_raw;entry.rule=(bits&1?HAPPY_BOX_MATCH:0)|(bits&2?PENALTY_BOX_USER_MATCH:0)|(bits&4?PENALTY_BOX_ADMIN_MATCH:0);
  uid.minimum=uid.maximum=entry_uid;bool actual_match=gta3xlwifi_raw_uid_mt(&skb,&p);
  bool expected_deny=denylist_xtbpf(&oracle)!=0;bool actual_deny=actual_match&&present&&(entry.rule&(PENALTY_BOX_USER_MATCH|PENALTY_BOX_ADMIN_MATCH));assert(actual_deny==expected_deny);++comparisons;
  bool expected_allow=allowlist_xtbpf(&oracle)!=0;bool actual_allow=gta3xlwifi_raw_appid_mt(&skb,&c)||(actual_match&&present&&(entry.rule&HAPPY_BOX_MATCH));assert(actual_allow==expected_allow);++comparisons;
 }
 T(strcmp(gta3xlwifi_raw_uid_reg[0].name,"gta3xlwifi_raw_uid")==0&&strcmp(gta3xlwifi_raw_uid_reg[1].name,"gta3xlwifi_raw_appid")==0);
 T(gta3xlwifi_raw_uid_reg[0].match==gta3xlwifi_raw_uid_mt&&gta3xlwifi_raw_uid_reg[1].match==gta3xlwifi_raw_appid_mt&&gta3xlwifi_raw_uid_reg[0].hooks==((1<<1)|(1<<2)|(1<<3)));
 register_result=-ENOMEM;T(gta3xlwifi_raw_uid_init()==-ENOMEM&&registers==1);register_result=0;T(gta3xlwifi_raw_uid_init()==0&&registers==2);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env);(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',r.stdout);assert match and int(match[1])>=19 and int(match[2])==896
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,source,header,appid_header,aids,reference,enum_header,O/'test.c',exported]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_android17_metered_predicate_comparisons':int(match[2]),'stderr':r.stderr,'command':cmd,'linux_helper_semantics_reference':'https://raw.githubusercontent.com/torvalds/linux/v6.6/net/core/filter.c','inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; actual raw matches vs A17 metered predicates, fatal UBSan fixtures')
