#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual private ingress predicates vs selected Android17 owner/discard C.

Packet parsing, exact-skb metadata and xtables registration are fixtures here;
the actual parser/context/lifecycle have separate tests. No automatic IIF policy,
rules, native compiler, packet hook completion or network readiness is validated.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
module=S/'net/netfilter/gta3xlwifi_ingress.c';table=S/'net/netfilter/gta3xlwifi_socket_tables.c';android=A/'packages/modules/Connectivity/bpf/progs/netd.c';ah=android.with_name('netd.h');source=module.read_text();at=android.read_text()
for rel in ['include/uapi/linux/netfilter/gta3xlwifi_ingress.h','include/uapi/linux/netfilter/gta3xlwifi_socket_tables.h','include/net/gta3xlwifi_packet.h']:
 p=S/rel;q=O/rel.replace('include/uapi/','include/');q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(p.read_bytes())
code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <linux/netfilter/gta3xlwifi_ingress.h>
#include <linux/netfilter/gta3xlwifi_socket_tables.h>
typedef uint32_t u32;typedef uint8_t u8;
#include <net/gta3xlwifi_packet.h>
#define GTA3XLWIFI_SOCKET_TABLE "g24sock"
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NFPROTO_UNSPEC 0
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define EXPORT_SYMBOL_GPL(x)
#define __read_mostly
#define __init
#define module_init(x)
#define THIS_MODULE NULL
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
struct net_device{u32 ifindex;};struct sk_buff{unsigned identity;};
struct xt_action_param{unsigned hooknum;const struct net_device*in;const void*matchinfo;};
struct xt_mtchk_param{const char*table;unsigned family;const void*matchinfo;};
struct xt_match{const char*name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void*me;};
struct xt_entry_match{union{struct{const struct xt_match*match;}kernel;}u;};
static unsigned init_user_ns,other_ns;static void*user_ns=&init_user_ns;
static void*current_user_ns(void){return user_ns;}
static bool have_context=true,dns,output,parse_result;
static struct gta3xlwifi_packet packet;
static struct sk_buff frame={1},clone={2};
static bool gta3xlwifi_socket_context_packet(const struct sk_buff*s,bool*d,bool*o){if(!have_context||s!=&frame)return false;*d=dns;*o=output;return true;}
bool gta3xlwifi_parse_packet(const struct sk_buff*s,struct gta3xlwifi_packet*p){assert(s==&frame);*p=packet;return parse_result;}
static int register_error;static unsigned registrations;
static int xt_register_matches(struct xt_match*,unsigned);
'''
code+=source[source.index('static bool ingress_registered;'):source.index('MODULE_LICENSE(')]
code+='\n'+m.extract(table.read_text(),'socket_match_safe')
code+=r'''
static int xt_register_matches(struct xt_match*m,unsigned n){assert(m==ingress_matches&&n==2);++registrations;return register_error;}
#define function
#define PASS 1
#define DROP 0
#define DROP_UNLESS_DNS 2
#define UID_RULES_CONFIGURATION_KEY 0
#define API_IS_AT_LEAST(level,version) 0
#define KVER_IS_AT_LEAST(k,a,b) ((k).version >= (((a)<<16)|((b)<<8)))
struct kver_uint{unsigned version;};struct sdk_level_uint{unsigned version;};struct egress_bool{bool egress;};
struct __sk_buff{u32 ifindex;};
typedef struct gta3xlwifi_packet SkbIpPacketData;
typedef struct{struct in6_addr daddr;}IngressDiscardKey;
typedef struct{u32 iif[2];}IngressDiscardValue;
typedef struct{u32 rule,iif;}UidOwnerValue;typedef u32 BpfConfig;
static bool protect;static struct in6_addr protected_addr;static IngressDiscardValue protected_iif;
static UidOwnerValue uid_entry;
static IngressDiscardValue*bpf_ingress_discard_map_lookup_elem(const IngressDiscardKey*k){return protect&&!memcmp(&k->daddr,&protected_addr,16)?&protected_iif:NULL;}
static bool is_system_uid(u32 uid){assert(uid==10001);return false;}
static bool skip_owner_match(const SkbIpPacketData*p,struct egress_bool e){(void)p;(void)e;return false;}
static BpfConfig getConfig(unsigned key){assert(key==0);return 0;}
static UidOwnerValue*bpf_uid_owner_map_lookup_elem(const u32*uid){assert(*uid==10001);return &uid_entry;}
static bool isBlockedByUidRules(u32 enabled,u32 rules){assert(!enabled);(void)rules;return false;}
'''
for name in ['IIF_MATCH','LOCKDOWN_VPN_MATCH','BACKGROUND_MATCH']:
 line=re.search(r'^\s*'+name+r'\s*=\s*\(1 << \d+\),',ah.read_text(),re.M);assert line;code+='enum {'+line[0].strip().rstrip(',')+'};\n'
code+='\n'+m.extract(at,'ingress_should_discard')+'\n'+m.extract(at,'bpf_owner_match')
code+=r'''
static unsigned cases,owner_comparisons,discard_comparisons;
#define T(x) do{assert(x);++cases;}while(0)
int main(void){
 T(sizeof(struct gta3xlwifi_bad_iif_match)==8&&sizeof(struct gta3xlwifi_ingress_discard_match)==28&&offsetof(struct gta3xlwifi_ingress_discard_match,allowed_ifindex)==16);
 T(gta3xlwifi_ingress_features()==0);register_error=-EINVAL;T(ingress_init()==-EINVAL&&gta3xlwifi_ingress_features()==0&&registrations==1);register_error=0;T(ingress_init()==0&&gta3xlwifi_ingress_features()==512&&registrations==2);
 T(ingress_matches[0].matchsize==8&&ingress_matches[1].matchsize==28&&ingress_matches[0].hooks==10&&ingress_matches[1].hooks==10);
 for(unsigned i=0;i<2;i++){struct xt_entry_match em={.u.kernel.match=&ingress_matches[i]};T(socket_match_safe(&em));}struct xt_match foreign={.name="owner"};struct xt_entry_match em={.u.kernel.match=&foreign};T(!socket_match_safe(&em));
 struct gta3xlwifi_bad_iif_match bad={17,0};struct gta3xlwifi_ingress_discard_match discard={{0}, {2,17},0};discard.daddr[15]=1;
 struct xt_mtchk_param check={"g24sock",NFPROTO_IPV4,&bad};T(bad_iif_check(&check)==0);bad.reserved=1;T(bad_iif_check(&check)==-EINVAL);bad.reserved=0;bad.allowed_ifindex=UINT32_MAX;T(bad_iif_check(&check)==-EINVAL);bad.allowed_ifindex=0;T(bad_iif_check(&check)==0);
 check.matchinfo=&discard;T(ingress_discard_check(&check)==0);discard.reserved=1;T(ingress_discard_check(&check)==-EINVAL);discard.reserved=0;discard.allowed_ifindex[0]=UINT32_MAX;T(ingress_discard_check(&check)==-EINVAL);discard.allowed_ifindex[0]=2;
 memset(discard.daddr,0,16);T(ingress_discard_check(&check)==-EINVAL);discard.daddr[10]=discard.daddr[11]=255;T(ingress_discard_check(&check)==-EINVAL);discard.daddr[15]=1;T(ingress_discard_check(&check)==0);
 for(unsigned family=0;family<4;family++){check.family=family;T(ingress_discard_check(&check)==(family==2?0:-EINVAL));}check.family=NFPROTO_IPV6;T(ingress_discard_check(&check)==0);check.table="filter";T(ingress_discard_check(&check)==-EINVAL);check.table="g24sock";user_ns=&other_ns;T(ingress_discard_check(&check)==-EINVAL);user_ns=&init_user_ns;
 const u32 indices[]={0,1,2,17,INT_MAX};const u32 allowed[]={0,2,17};struct net_device dev={17};struct xt_action_param action={NF_INET_LOCAL_IN,&dev,&bad};struct __sk_buff oracle={17};packet.ip_version=4;
 // IIF-present wildcard0 suppresses lockdown. The native compiler must emit no
 // drop entry for that UID; absent-IIF lockdown uses bad_iif allowed0 instead.
 for(unsigned present=0;present<2;present++)for(unsigned lockdown=0;lockdown<2;lockdown++)for(unsigned a=0;a<3;a++)for(unsigned i=0;i<5;i++)for(unsigned d=0;d<2;d++)for(unsigned o=0;o<2;o++){
  dns=d;output=o;dev.ifindex=oracle.ifindex=indices[i];action.hooknum=output?NF_INET_LOCAL_OUT:NF_INET_LOCAL_IN;uid_entry=(UidOwnerValue){(present?IIF_MATCH:0)|(lockdown?LOCKDOWN_VPN_MATCH:0),allowed[a]};
  int match=bpf_owner_match(&packet,&oracle,10001,(struct egress_bool){output},(struct kver_uint){(4<<16)|(19<<8)},(struct sdk_level_uint){0});bool expected=match==DROP||(match==DROP_UNLESS_DNS&&!dns);
  bool have_rule=present?allowed[a]!=0:lockdown;bad.allowed_ifindex=present?allowed[a]:0;bool actual=have_rule&&bad_iif_match(&frame,&action);assert(actual==expected);++owner_comparisons;
 }
 // Exact A17 discard expression, including partial L4 parse, two allowed
 // interfaces, loopback/output and DNS having NO discard exemption.
 protect=true;protected_addr=(struct in6_addr){{{0}}};protected_addr.s6_addr[15]=1;memcpy(discard.daddr,&protected_addr,16);action.matchinfo=&discard;
 for(unsigned version=0;version<3;version++)for(unsigned a=0;a<3;a++)for(unsigned b=0;b<3;b++)for(unsigned i=0;i<5;i++)for(unsigned d=0;d<2;d++)for(unsigned o=0;o<2;o++)for(unsigned same=0;same<2;same++)for(unsigned parsed=0;parsed<2;parsed++){
  dns=d;output=o;parse_result=parsed;dev.ifindex=oracle.ifindex=indices[i];action.hooknum=output?NF_INET_LOCAL_OUT:NF_INET_LOCAL_IN;discard.allowed_ifindex[0]=protected_iif.iif[0]=allowed[a];discard.allowed_ifindex[1]=protected_iif.iif[1]=allowed[b];packet.ip_version=version?version==1?4:6:0;packet.daddr=protected_addr;if(!same)packet.daddr.s6_addr[15]=2;
  bool expected=!output&&oracle.ifindex!=1&&ingress_should_discard(&packet,&oracle,(struct kver_uint){(4<<16)|(19<<8)});assert(ingress_discard_match(&frame,&action)==expected);++discard_comparisons;
 }
 output=false;dns=false;dev.ifindex=17;action.hooknum=NF_INET_LOCAL_IN;action.matchinfo=&bad;bad.allowed_ifindex=0;T(bad_iif_match(&frame,&action));T(!bad_iif_match(&clone,&action));have_context=false;T(!bad_iif_match(&frame,&action));have_context=true;u32 sentinel=777;T(!ingress_context(NULL,&action,false,&sentinel)&&sentinel==777);T(!ingress_context(&frame,NULL,false,&sentinel)&&sentinel==777);action.hooknum=2;T(!bad_iif_match(&frame,&action));action.hooknum=NF_INET_LOCAL_IN;action.in=NULL;T(bad_iif_match(&frame,&action));
 printf("passed_cases=%u owner_comparisons=%u discard_comparisons=%u\n",cases,owner_comparisons,discard_comparisons);
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=30,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
match=re.fullmatch(r'passed_cases=(\d+) owner_comparisons=(\d+) discard_comparisons=(\d+)\n',r.stdout);assert match and int(match[2])==240 and int(match[3])==2160
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,module,table,android,ah,O/'test.c',*[p for p in (O/'include').rglob('*.h')],S/'include/net/gta3xlwifi_socket_tables.h']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_A17_owner_comparisons':int(match[2]),'actual_A17_discard_comparisons':int(match[3]),'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip())
