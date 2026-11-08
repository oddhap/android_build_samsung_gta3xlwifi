#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual private socket-table lifecycle/grammar/evaluator/lease helper C.

Table allocation/translation/evaluation, netns, sockets, RCU and credentials are
fixtures. Checks exact core insertion boundaries; no global hook, real packets,
complete owner policy, iptables syscall or readiness is validated by this test.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-kernel','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_kernel.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
module=S/'net/netfilter/gta3xlwifi_socket_tables.c';d=S/'net/netfilter/gta3xlwifi_netpolicy.c';text=module.read_text();dt=d.read_text()
assert 'late_initcall(socket_tables_init)' in text and 'module_init(socket_tables_init)' not in text
stripped=re.sub(r'/\*.*?\*/','',text,flags=re.S);assert not re.search(r'\b(?:xt_hook_link|nf_register_hooks?|nf_register_net_hooks?)\s*\(',stripped)
def core_function(s):
 pos=s.index('__do_replace(');start=s.rfind('static int',0,pos);i=s.index('{',pos);depth=1;j=i+1
 while depth:
  if s[j]=='{':depth+=1
  elif s[j]=='}':depth-=1
  j+=1
 return s[start:j]
cores=[]
for family,rel in [(4,'net/ipv4/netfilter/ip_tables.c'),(6,'net/ipv6/netfilter/ip6_tables.c')]:
 p=S/rel;q=B/rel;new=core_function(p.read_text());before=core_function(q.read_text())
 validation='\tret = gta3xlwifi_socket_rules'+str(family)+'(name, newinfo);\n\tif (ret)\n\t\treturn ret;\n\n'
 begin='\tsocket_lease = gta3xlwifi_socket_update_begin(name);\n\tif (socket_lease < 0) {\n\t\tret = socket_lease;\n\t\tsocket_lease = 0;\n\t\tgoto put_module;\n\t}\n'
 assert new.count(validation)==1 and new.count(begin)==1 and new.count('gta3xlwifi_socket_update_end(socket_lease);')==2
 assert new.replace('int ret, socket_lease = 0;','int ret;',1).replace(validation,'',1).replace(begin,'',1).replace('\tgta3xlwifi_socket_update_end(socket_lease);\n','')==before
 assert new.index('gta3xlwifi_socket_rules')<new.index('xt_replace_table(') and new.index('gta3xlwifi_socket_update_begin')<new.index('xt_replace_table(')
 # Both native/compat paths reach the same checked replacement after translation.
 assert p.read_text().count('__do_replace(')>=3;cores.extend([p,q])
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
typedef uint32_t u32;typedef uint8_t u8;
#define IS_ENABLED(x) (x)
#define CONFIG_IP6_NF_IPTABLES 1
#define __net_init
#define __net_exit
#define __init
#define THIS_MODULE NULL
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3
#define NF_ACCEPT 1
#define NF_DROP 0
#define NF_IP_PRI_FILTER 0
#define NF_IP6_PRI_FILTER 0
#define XT_STANDARD_TARGET ""
#define XT_ERROR_TARGET "ERROR"
#define XT_RETURN (-5)
#define GTA3XLWIFI_SOCKET_TABLE "g24sock"
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define late_initcall(x)
#define smp_store_release(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
#define READ_ONCE(p) __atomic_load_n(&(p),__ATOMIC_RELAXED)
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
struct xt_match{const char*name;};struct xt_target{const char*name;};
struct xt_entry_match{union{struct{struct xt_match*match;}kernel;}u;};
struct xt_entry_target{union{struct{struct xt_target*target;}kernel;}u;};
struct xt_standard_target{struct xt_entry_target target;int verdict;};
struct xt_table{char name[32];unsigned valid_hooks;void*me;u8 af;int priority;};
#define ENTRY_FIELDS unsigned match_count;struct xt_entry_match matches[4];struct xt_standard_target target
struct ipt_entry{ENTRY_FIELDS;};struct ip6t_entry{ENTRY_FIELDS;};
struct xt_table_info{void*entries;unsigned size;};
#define xt_entry_foreach(e,base,size) for((e)=(base);(char*)(e)<(char*)(base)+(size);++(e))
#define xt_ematch_foreach(m,e) for((m)=(e)->matches;(m)<(e)->matches+(e)->match_count;++(m))
static struct xt_entry_target*ipt_get_target(struct ipt_entry*e){return &e->target.target;}
static struct xt_entry_target*ip6t_get_target(struct ip6t_entry*e){return &e->target.target;}
struct ipt_standard{struct {int verdict;}target;};struct ip6t_standard{struct {int verdict;}target;};
struct ipt_replace{struct ipt_standard entries[2];};struct ip6t_replace{struct ip6t_standard entries[2];};
'''
start=text.index('struct socket_tables {');end=text.index('};',start)+2;code+=text[start:end]+r'''
struct net{struct socket_tables tables;};static struct net net0,net1;
struct sock{bool full;unsigned sk_family;struct net*net;u32 uid;};
struct net_device{unsigned ifindex;};
struct sk_buff{unsigned char*head,*data,*network;unsigned len,data_len;struct sock*sk;struct net_device*dev;unsigned short protocol;void(*destructor)(struct sk_buff*);};
struct nf_hook_state{unsigned hook;int thresh;u8 pf;struct net_device*in,*out;struct sock*sk;struct net*net;void*hook_list;void*okfn;};
struct pernet_operations{unsigned*id;size_t size;int(*init)(struct net*);void(*exit)(struct net*);};
static unsigned alloc_calls,alloc_fail_at,allocs,frees,reg_calls,reg_fail_at,table_allocs,table_frees,eval_calls,rcu_depth,destructor_calls;
static bool held=true,privileged=true;static int reg_subsys_error;static unsigned last_hook,last_pf,last_ifindex,observed_len;static u32 observed_uid;static unsigned result_verdict=NF_ACCEPT;
static void*netpolicy_owner_file;static pthread_mutex_t netpolicy_lock=PTHREAD_MUTEX_INITIALIZER;
#define mutex_lock(m) assert(pthread_mutex_lock(m)==0)
#define mutex_unlock(m) assert(pthread_mutex_unlock(m)==0)
#define netpolicy_held held
static bool netpolicy_privileged(void){return privileged;}
static bool gta3xlwifi_netpolicy_held(void){return held;}
static void rcu_read_lock(void){++rcu_depth;}static void rcu_read_unlock(void){assert(rcu_depth);--rcu_depth;}
static void*net_generic(struct net*n,unsigned id){assert(id==7);return &n->tables;}
static bool sk_fullsock(const struct sock*s){return s->full;}static struct net*sock_net(struct sock*s){return s->net;}
static unsigned char*skb_network_header(const struct sk_buff*s){return s->network;}
static unsigned skb_headroom(const struct sk_buff*s){return s->data-s->head;}
static unsigned skb_headlen(const struct sk_buff*s){return s->len-s->data_len;}
static unsigned ip_hdrlen(const struct sk_buff*s){return (s->network[0]&15)*4;}
static void __skb_push(struct sk_buff*s,unsigned n){assert(n<=skb_headroom(s));s->data-=n;s->len+=n;}
static void __skb_pull(struct sk_buff*s,unsigned n){assert(n<=s->len);s->data+=n;s->len-=n;}
static void destructor(struct sk_buff*s){(void)s;++destructor_calls;}
static void*kalloc(size_t n){if(++alloc_calls==alloc_fail_at)return NULL;void*p=calloc(1,n);assert(p);++allocs;return p;}
static void kfree(void*p){if(p){++frees;free(p);}}
static void*ipt_alloc_initial_table(const struct xt_table*t){assert(!strcmp(t->name,"g24sock")&&t->af==2&&t->valid_hooks==10);return kalloc(sizeof(struct ipt_replace));}
static void*ip6t_alloc_initial_table(const struct xt_table*t){assert(!strcmp(t->name,"g24sock")&&t->af==10&&t->valid_hooks==10);return kalloc(sizeof(struct ip6t_replace));}
static struct xt_table*register_table(struct net*n,const struct xt_table*t){assert(n);if(++reg_calls==reg_fail_at)return (void*)(intptr_t)-EIO;struct xt_table*table=malloc(sizeof(*table));assert(table);*table=*t;++table_allocs;return table;}
static struct xt_table*ipt_register_table(struct net*n,const struct xt_table*t,const struct ipt_replace*r){assert(r->entries[0].target.verdict==-1&&r->entries[1].target.verdict==-1);return register_table(n,t);}
static struct xt_table*ip6t_register_table(struct net*n,const struct xt_table*t,const struct ip6t_replace*r){assert(r->entries[0].target.verdict==-1&&r->entries[1].target.verdict==-1);return register_table(n,t);}
static void ipt_unregister_table(struct net*n,struct xt_table*t){assert(n&&t&&!IS_ERR(t)&&t->af==2);++table_frees;free(t);}
static void ip6t_unregister_table(struct net*n,struct xt_table*t){assert(n&&t&&!IS_ERR(t)&&t->af==10);++table_frees;free(t);}
static int register_pernet_subsys(struct pernet_operations*o){assert(o->id&&o->size==sizeof(struct socket_tables));if(reg_subsys_error)return reg_subsys_error;*o->id=7;return o->init(&net0);}
static unsigned evaluate(struct sk_buff*s,const struct nf_hook_state*st,struct xt_table*t){assert(rcu_depth==1&&s->sk==st->sk&&st->net==s->sk->net&&s->data==s->network&&t->af==st->pf);assert((st->hook==1&&st->in==s->dev&&!st->out)||(st->hook==3&&!st->in&&st->out==s->dev));last_hook=st->hook;last_pf=st->pf;last_ifindex=s->dev?s->dev->ifindex:0;observed_len=s->len;observed_uid=s->sk->uid;++eval_calls;return result_verdict;}
static unsigned ipt_do_table(struct sk_buff*s,const struct nf_hook_state*st,struct xt_table*t){assert(st->pf==2);return evaluate(s,st,t);}
static unsigned ip6t_do_table(struct sk_buff*s,const struct nf_hook_state*st,struct xt_table*t){assert(st->pf==10);return evaluate(s,st,t);}
'''
code+='\n'.join(m.extract(dt,n) for n in ['gta3xlwifi_socket_update_begin','gta3xlwifi_socket_update_end'])+'\n'
# The production struct is already defined above to type the netns fixture.
body=text[text.index('#define SOCKET_HOOKS'):text.index('MODULE_LICENSE(')];body=body.replace(text[start:end],'');code+=body
code+=r'''
static unsigned cases,comparisons;
#define T(x) do{++cases;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}}while(0)
static void reset(void){assert(allocs==frees&&table_allocs==table_frees);memset(&net0,0,sizeof(net0));memset(&net1,0,sizeof(net1));alloc_calls=alloc_fail_at=reg_calls=reg_fail_at=0;reg_subsys_error=0;socket_tables_registered=false;held=true;privileged=true;netpolicy_owner_file=NULL;}
int main(void){
 reset();reg_subsys_error=-EIO;T(socket_tables_init()==-EIO&&!socket_tables_registered);
 for(unsigned fail=1;fail<=2;fail++){reset();alloc_fail_at=fail;T(socket_tables_init()==-ENOMEM&&!socket_tables_registered&&allocs==frees&&table_allocs==table_frees&&!net0.tables.v4&&!net0.tables.v6);reset();reg_fail_at=fail;T(socket_tables_init()==-EIO&&!socket_tables_registered&&allocs==frees&&table_allocs==table_frees&&!net0.tables.v4&&!net0.tables.v6);}
 reset();T(socket_tables_init()==0&&socket_tables_registered&&net0.tables.v4&&net0.tables.v6);T(socket_tables_net_init(&net1)==0&&net1.tables.v4&&net1.tables.v6&&net1.tables.v4!=net0.tables.v4);
 // Real whitelist helpers, using already-translated target/match fixture layouts.
 struct xt_target standard={""},error={"ERROR"},reject={"REJECT"},queue={"NFQUEUE"};struct xt_match matches[]={{"gta3xlwifi_raw_uid"},{"gta3xlwifi_raw_appid"},{"gta3xlwifi_owner_skip"},{"gta3xlwifi_non_loopback"},{"owner"},{"gta3xlwifi_raw_uidX"}};
 struct ipt_entry e4={0};struct ip6t_entry e6={0};struct xt_table_info i4={&e4,sizeof(e4)},i6={&e6,sizeof(e6)};
 for(unsigned family=0;family<2;family++)for(unsigned target=0;target<4;target++)for(int verdict=-8;verdict<10;verdict++)for(unsigned match=0;match<6;match++){
  struct xt_target*t=target==0?&standard:target==1?&error:target==2?&reject:&queue;e4.match_count=e6.match_count=1;e4.matches[0].u.kernel.match=e6.matches[0].u.kernel.match=&matches[match];e4.target.target.u.kernel.target=e6.target.target.u.kernel.target=t;e4.target.verdict=e6.target.verdict=verdict;
  bool allowed=match<4&&(target==1||(target==0&&(verdict>=0||verdict==-1||verdict==-2||verdict==-5)));
  int actual=family?gta3xlwifi_socket_rules6("g24sock",&i6):gta3xlwifi_socket_rules4("g24sock",&i4);assert(actual==(allowed?0:-EINVAL));assert((family?gta3xlwifi_socket_rules6("filter",&i6):gta3xlwifi_socket_rules4("filter",&i4))==0);++comparisons;
 }
 T(comparisons==864);T(gta3xlwifi_socket_update_begin("filter")==0);privileged=false;T(gta3xlwifi_socket_update_begin("g24sock")==-EPERM);privileged=true;T(gta3xlwifi_socket_update_begin("g24sock")==-EBUSY);netpolicy_owner_file=&net0;held=false;T(gta3xlwifi_socket_update_begin("g24sock")==-EBUSY);held=true;T(gta3xlwifi_socket_update_begin("g24sock")==1);T(pthread_mutex_trylock(&netpolicy_lock)==EBUSY);gta3xlwifi_socket_update_end(0);T(pthread_mutex_trylock(&netpolicy_lock)==EBUSY);gta3xlwifi_socket_update_end(1);T(pthread_mutex_trylock(&netpolicy_lock)==0);T(pthread_mutex_unlock(&netpolicy_lock)==0);
 unsigned char bytes[256]={0};struct net_device dev={17};struct sock owner={true,AF_INET,&net1,10001},foreign={true,AF_INET,&net0,0};
 struct sk_buff skb={bytes,bytes+34,bytes+14,180,0,&foreign,&dev,htons(ETH_P_IP),destructor};bytes[14]=0x45;
 struct sk_buff saved=skb;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&!memcmp(&skb,&saved,sizeof(skb))&&eval_calls==0);held=false;
 for(unsigned family=0;family<2;family++)for(unsigned direction=0;direction<2;direction++)for(unsigned verdict=0;verdict<6;verdict++){
  skb.protocol=htons(family?ETH_P_IPV6:ETH_P_IP);bytes[14]=family?0x60:0x45;saved=skb;result_verdict=verdict;unsigned before=eval_calls;
  T(gta3xlwifi_socket_table_policy(&owner,&skb,direction)==(verdict==NF_ACCEPT?0:-EPERM)&&eval_calls==before+1&&!memcmp(&skb,&saved,sizeof(skb))&&last_pf==(family?10:2)&&last_hook==(direction?3:1)&&observed_uid==10001&&observed_len==200&&last_ifindex==17&&!destructor_calls&&!rcu_depth);
 }
 // IPv4 carried by AF_INET6 still selects packet-family4; inode UID changes are honored.
 owner.sk_family=AF_INET6;owner.uid=10002;skb.protocol=htons(ETH_P_IP);bytes[14]=0x45;result_verdict=NF_ACCEPT;saved=skb;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==0&&observed_uid==10002&&last_pf==2&&!memcmp(&skb,&saved,sizeof(skb)));
 unsigned before=eval_calls;T(gta3xlwifi_socket_table_policy(NULL,&skb,false)==0);owner.full=false;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==0);owner.full=true;owner.sk_family=AF_UNIX;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==0&&eval_calls==before);owner.sk_family=AF_INET;
 skb.network=skb.data+1;saved=skb;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&!memcmp(&skb,&saved,sizeof(skb)));skb.network=bytes+14;skb.len=0;skb.data_len=0;skb.data=bytes+14;saved=skb;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&!memcmp(&skb,&saved,sizeof(skb))&&eval_calls==before);
 skb=saved;skb.len=200;bytes[14]=0x44;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&eval_calls==before);bytes[14]=0x45;skb.protocol=0;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&eval_calls==before);skb.protocol=htons(ETH_P_IP);struct xt_table*old=net1.tables.v4;net1.tables.v4=NULL;T(gta3xlwifi_socket_table_policy(&owner,&skb,false)==-EPERM&&eval_calls==before);net1.tables.v4=old;
 socket_tables_net_exit(&net1);socket_tables_net_exit(&net0);socket_tables_registered=false;T(allocs==frees&&table_allocs==table_frees&&!net0.tables.v4&&!net0.tables.v6&&!net1.tables.v4&&!net1.tables.v6&&!destructor_calls&&!rcu_depth);
 printf("passed_cases=%u grammar_comparisons=%u\n",cases,comparisons);return 0;
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread',str(O/'test.c'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=30,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
match=re.fullmatch(r'passed_cases=(\d+) grammar_comparisons=(\d+)\n',r.stdout);assert match and int(match[2])==864
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,module,d,S/'include/net/gta3xlwifi_socket_tables.h',*cores,O/'test.c'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'grammar_comparisons':int(match[2]),'core_replacement_bodies_preserved_except_exact_private_inserts':True,'no_global_nf_hooks_registered':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; actual private table C, fatal UBSan fixtures')
