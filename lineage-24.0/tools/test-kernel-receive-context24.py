#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual socket-aware receive LNA/tag query/filter hook with real store/parser C.

Copies/RCU, sockets, qtaguid lookup and skb are fixtures. Real pthread contention
checks HOLD drains a receive reader. Actual A17 parser/permission expressions
and unchanged old receive/LSM/filter ordering are checked. No device packets.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-kernel','store-host','packet-host','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_kernel.resolve();O=a.output.resolve();A=a.android_source.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
prior=a.store_host/'report.json';r=json.loads(prior.read_text());assert r['passed'];src=a.store_host/'test.c';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();assert sha(src)==r['inputs_sha256'][str(src)]
store=B/'net/netfilter/gta3xlwifi_local_network.c';assert sha(store)==next(h for p,h in r['inputs_sha256'].items() if p.endswith('/gta3xlwifi_local_network.c'))
code=src.read_text().split('int main(void){',1)[0].replace('static u32 state=0x12345678;static u32 random32','static u32 state=0x12345678;\nstatic u32 random32')
for n in ['tx','compare','random32','reference_image','check_decision']:code=code.replace(m.extract(code,n),'')
code=code.replace('static u32 state=0x12345678;','').replace('static unsigned cases,comparisons;','static unsigned cases;').replace('parent_pid,child_pid','parent_pid').replace('owner={1},foreign={2}','owner={1}')
coord=r'''
#include <pthread.h>
#include <assert.h>
#include <stdbool.h>
static pthread_mutex_t rmu=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rcv=PTHREAD_COND_INITIALIZER;
static unsigned active_readers;static bool pause_tag,tag_entered,continue_tag,drain_entered,hold_done;
static void wait_readers(void){assert(pthread_mutex_lock(&rmu)==0);while(active_readers)pthread_cond_wait(&rcv,&rmu);assert(pthread_mutex_unlock(&rmu)==0);}
'''
code=coord+code.replace('network_graces,rcu_graces,rcu_depth,allocs,frees;','network_graces,rcu_graces,allocs,frees;static __thread unsigned rcu_depth;')
code=code.replace(m.extract(code,'rcu_read_lock'),'static void rcu_read_lock(void){assert(pthread_mutex_lock(&rmu)==0);if(!rcu_depth++)++active_readers;assert(pthread_mutex_unlock(&rmu)==0);}')
code=code.replace(m.extract(code,'rcu_read_unlock'),'static void rcu_read_unlock(void){assert(pthread_mutex_lock(&rmu)==0);assert(rcu_depth);if(!--rcu_depth)--active_readers;pthread_cond_broadcast(&rcv);assert(pthread_mutex_unlock(&rmu)==0);}')
code=code.replace(m.extract(code,'synchronize_net'),'static void synchronize_net(void){++network_graces;assert(pthread_mutex_lock(&rmu)==0);drain_entered=true;pthread_cond_broadcast(&rcv);while(active_readers)pthread_cond_wait(&rcv,&rmu);assert(pthread_mutex_unlock(&rmu)==0);}')
code=code.replace('static void synchronize_rcu(void){','static void synchronize_rcu(void){wait_readers();')
raw=S/'net/netfilter/xt_qtaguid.c';internal=S/'net/netfilter/xt_qtaguid_internal.h';rt=raw.read_text();it=internal.read_text();parser=S/'net/netfilter/gta3xlwifi_packet.c';filter=S/'net/core/filter.c';reference_filter=B/'net/core/filter.c'
new_hook=m.extract(filter.read_text(),'sk_filter_trim_cap');old_hook=m.extract(reference_filter.read_text(),'sk_filter_trim_cap');insert='\terr = gta3xlwifi_receive_policy(sk, skb);\n\tif (err)\n\t\treturn err;\n\n';assert new_hook.replace(insert,'')==old_hook and new_hook.count('gta3xlwifi_receive_policy(')==1
assert '#include <net/gta3xlwifi_receive.h>' in filter.read_text()
assert 'synchronize_rcu();' in m.extract((B/'net/core/dev.c').read_text(),'synchronize_net')
android=A/'packages/modules/Connectivity/bpf/progs/netd.c';aids=A/'system/core/libcutils/include/private/android_filesystem_config.h';assert re.search(r'#define AID_DNS\s+1051\b',aids.read_text()) and '#define TAG_SYSTEM_DNS 0xFFFFFF82' in android.read_text()
code+=r'''
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <net/gta3xlwifi_packet.h>
struct net{const void*user_ns;};struct bpf_prog{unsigned value;};struct sk_filter{struct bpf_prog*prog;};
struct sock{u32 uid,creator_uid;bool full,memalloc;unsigned sk_family;struct net*net;struct sk_filter*sk_filter;};
struct net_device{u32 ifindex;};struct sk_buff{u8 data[1200];int data_at,network;unsigned length;u16 protocol;struct sock*sk;struct net_device*dev;bool pfmemalloc;};
static bool sk_fullsock(const struct sock*s){return s->full;}
static struct net*sock_net(struct sock*s){return s->net;}
static u32 sock_net_uid(struct net*n,struct sock*s){assert(s->net==n);return s->uid;}
static u32 from_kuid_munged(const void*n,u32 uid){assert(n==&init_user_ns);return uid;}
static int skb_network_offset(const struct sk_buff*s){return s->network;}
static int skb_copy_bits(const struct sk_buff*s,int off,void*out,int count){if(off < -s->data_at || off+count>(int)s->length)return -EFAULT;memcpy(out,s->data+s->data_at+off,count);return 0;}
typedef u64 tag_t;
struct sock_tag{tag_t tag;};static struct sock_tag tagged;static const struct sock*tagged_sk;
static bool module_passive,poison_tag;static unsigned tag_lookups,tag_depth;
static pthread_mutex_t sock_tag_list_lock=PTHREAD_MUTEX_INITIALIZER;
#define spin_lock_bh(lock) do{assert(pthread_mutex_lock(lock)==0);++tag_depth;}while(0)
#define spin_unlock_bh(lock) do{assert(tag_depth==1);--tag_depth;if(poison_tag)tagged.tag=0;assert(pthread_mutex_unlock(lock)==0);}while(0)
static struct sock_tag*get_sock_stat_nl(const struct sock*s){assert(tag_depth==1);++tag_lookups;assert(pthread_mutex_lock(&rmu)==0);if(pause_tag){tag_entered=true;pthread_cond_broadcast(&rcv);while(!continue_tag)pthread_cond_wait(&rcv,&rmu);}assert(pthread_mutex_unlock(&rmu)==0);return s==tagged_sk?&tagged:NULL;}
'''
if 'result = gta3xlwifi_socket_table_policy_uid(' in rt:
 code+='\nstatic int gta3xlwifi_socket_table_policy_uid(struct sock*s,struct sk_buff*b,bool o,u32 u){(void)s;(void)b;(void)o;(void)u;assert(rcu_depth);return 0;} /* scoped LNA fixture; DROP/snapshot/order tested separately */\n'
code+='\n'.join(line for line in it.splitlines() if line.startswith('#define TAG_UID_MASK ') or line.startswith('#define TAG_ACCT_MASK '))+'\n'+'\n'.join(m.extract(it,n) for n in ['get_uid_from_tag','get_atag_from_tag'])+'\n'+'\n'.join(m.extract(parser.read_text(),n) for n in ['gta3xlwifi_packet_read','gta3xlwifi_parse_packet'])+'\n'+'\n'.join(m.extract(rt,n) for n in ['gta3xlwifi_socket_accounting','gta3xlwifi_receive_features','gta3xlwifi_receive_policy'])
# Reuse the actual A17 parser/oracle text from its hash-bound previous host run.
pp=a.packet_host/'test.c';pp_report=json.loads((a.packet_host/'report.json').read_text());assert pp_report['passed'] and sha(pp)==pp_report['inputs_sha256'][str(pp)]
ptext=pp.read_text();oracle=ptext[ptext.index('struct tcphdr_with_flags16 {'):ptext.index('static unsigned cases,comparisons,dispatches;')];code+='\n'+oracle
code+=r'''
#define SOCK_MEMALLOC 1
#define max(a,b) ((a)>(b)?(a):(b))
static int lsm_error,trim_error;static unsigned lsm_calls,filter_calls,trim_calls;
static bool skb_pfmemalloc(const struct sk_buff*s){return s->pfmemalloc;}
static bool sock_flag(const struct sock*s,int flag){assert(flag==SOCK_MEMALLOC);return s->memalloc;}
static int security_sock_rcv_skb(struct sock*s,struct sk_buff*b){assert(s&&b);++lsm_calls;return lsm_error;}
static unsigned bpf_prog_run_save_cb(struct bpf_prog*p,struct sk_buff*b){assert(b&&lsm_calls);++filter_calls;return p->value;}
static int pskb_trim(struct sk_buff*b,unsigned count){++trim_calls;if(trim_error)return trim_error;if(b->length>count)b->length=count;return 0;}
'''+new_hook+r'''
static struct net net={&init_user_ns};static struct net_device device={17};
static struct sock receiver={.uid=10001,.creator_uid=777,.full=true,.sk_family=AF_INET,.net=&net};
static struct sock foreign={.uid=0,.full=true,.sk_family=AF_INET,.net=&net};
static int receive_result,hold_result;
static void*receive_thread(void*x){receive_result=gta3xlwifi_receive_policy(&receiver,x);return NULL;}
static void*hold_thread(void*x){(void)x;hold_result=netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0);assert(pthread_mutex_lock(&rmu)==0);hold_done=true;pthread_cond_broadcast(&rcv);assert(pthread_mutex_unlock(&rmu)==0);return NULL;}
static unsigned parse_comparisons;
static void packet_check(struct sk_buff*s){struct gta3xlwifi_packet actual;SkbIpPacketData expected={0};struct __sk_buff o={s,s->protocol};bool a=gta3xlwifi_parse_packet(s,&actual),b=parse_skb(&expected,&o,(struct kver_uint){515});assert(a==b&&!memcmp(&actual,&expected,40));++parse_comparisons;}
int main(void){
 T(gta3xlwifi_receive_features()==32);T(netpolicy_open(NULL,&owner)==0);
 struct gta3xlwifi_lna_entry deny={.allowed=0};struct gta3xlwifi_lna_transfer image={1,1,0,0,1,(uintptr_t)&deny,0};T(io(GTA3XLWIFI_LNA_SET_IMAGE,&image)==0);
 onetwork=&deny;oncount=1;ohost=NULL;ohcount=0;
 struct sk_buff skb={.length=1200-34,.data_at=34,.network=-20,.protocol=htons(ETH_P_IP),.sk=&foreign,.dev=&device};skb.data[14]=0x45;skb.data[23]=17;skb.data[26]=192;skb.data[29]=7;
 T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM);T(tag_lookups==0);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
 T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM&&skb.sk==&foreign&&skb.data_at==34&&skb.network==-20);T(oracle_blocked(receiver.uid,17,&(struct in6_addr){0},17,0));
 skb.sk=NULL;T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM&&skb.sk==NULL);
 receiver.creator_uid=0;T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM);receiver.uid=0;T(gta3xlwifi_receive_policy(&receiver,&skb)==0);receiver.uid=10001;
 T(gta3xlwifi_receive_policy(NULL,&skb)==0);T(gta3xlwifi_receive_policy(&receiver,NULL)==0);receiver.full=false;T(gta3xlwifi_receive_policy(&receiver,&skb)==0);receiver.full=true;receiver.sk_family=AF_UNIX;T(gta3xlwifi_receive_policy(&receiver,&skb)==0);receiver.sk_family=AF_INET6;T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM);receiver.sk_family=AF_INET;
 u32 stats=777,tag=888;T(gta3xlwifi_socket_accounting(NULL,&stats,&tag)==-EINVAL&&stats==777&&tag==888);T(gta3xlwifi_socket_accounting(&receiver,NULL,&tag)==-EINVAL);T(gta3xlwifi_socket_accounting(&receiver,&stats,NULL)==-EINVAL);T(gta3xlwifi_socket_accounting(&receiver,&stats,&tag)==-ENOENT&&stats==777&&tag==888);
 tagged_sk=&receiver;tagged.tag=((u64)0xffffff82<<32)|1051;poison_tag=true;T(gta3xlwifi_socket_accounting(&receiver,&stats,&tag)==0&&stats==1051&&tag==0xffffff82&&tagged.tag==0);poison_tag=false;
 tagged.tag=((u64)0xffffff82<<32)|1051;T(gta3xlwifi_receive_policy(&receiver,&skb)==0);
 tagged.tag=((u64)0xffffff81<<32)|1051;T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM);
 tagged.tag=((u64)0xffffff82<<32)|10001;T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM);
 tagged.tag=((u64)0xffffff82<<32)|1051;module_passive=true;stats=777;tag=888;T(gta3xlwifi_socket_accounting(&receiver,&stats,&tag)==-EOPNOTSUPP&&stats==777&&tag==888);T(gta3xlwifi_receive_policy(&receiver,&skb)==-EOPNOTSUPP);module_passive=false;

 tagged_sk=NULL;receiver.uid=1051;T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM);receiver.uid=10001;
 T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0);
 struct gta3xlwifi_uid_permission_entry entry={10001,1};struct gta3xlwifi_uid_permission_transfer permission={1,1,1,(uintptr_t)&entry};T(io(GTA3XLWIFI_UID_SET_IMAGE,&permission)==0);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
 T(gta3xlwifi_receive_policy(&receiver,&skb)==0);receiver.uid=10002;T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM);receiver.uid=10001;
 T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0);permission.count=0;permission.entries=0;permission.revision=2;T(io(GTA3XLWIFI_UID_SET_IMAGE,&permission)==0);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
 tagged_sk=&receiver;tagged.tag=((u64)0xffffff82<<32)|1051;
 T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0);T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);tagged_sk=NULL;
 // Existing socket-filter behavior/LSM errors are retained after the new check.
 struct bpf_prog prog={0};struct sk_filter socket_filter={&prog};receiver.sk_filter=&socket_filter;
 skb.pfmemalloc=true;T(sk_filter_trim_cap(&receiver,&skb,1)==-ENOMEM&&lsm_calls==0&&filter_calls==0);skb.pfmemalloc=false;
 T(sk_filter_trim_cap(&receiver,&skb,1)==-EPERM&&lsm_calls==0&&filter_calls==0);
 tagged_sk=&receiver;tagged.tag=((u64)0xffffff82<<32)|1051;lsm_error=-EACCES;T(sk_filter_trim_cap(&receiver,&skb,1)==-EACCES&&lsm_calls==1&&filter_calls==0);lsm_error=0;
 T(sk_filter_trim_cap(&receiver,&skb,1)==-EPERM&&lsm_calls==2&&filter_calls==1&&trim_calls==0);
 prog.value=80;unsigned oldlength=skb.length;T(sk_filter_trim_cap(&receiver,&skb,100)==0&&skb.length==100&&trim_calls==1);skb.length=oldlength;receiver.sk_filter=NULL;T(sk_filter_trim_cap(&receiver,&skb,1)==0);tagged_sk=NULL;
 // Full parser values remain correct with L3 both before and after skb data.
 for(unsigned family=0;family<2;family++)for(int at=0;at<=100;at+=10)for(unsigned proto=0;proto<256;proto++){
  skb.data_at=at;skb.network=14-at;skb.length=1200-at;skb.protocol=htons(family?ETH_P_IPV6:ETH_P_IP);for(unsigned i=0;i<1200;i++)skb.data[i]=(i*7+proto)&255;skb.data[14]=0x45;skb.data[23]=proto;skb.data[20]=proto;packet_check(&skb);
 }
 // Real owner HOLD must wait for a receive reader that observed the old open gate.
 skb.data_at=34;skb.network=-20;skb.length=1166;skb.protocol=htons(ETH_P_IP);memset(skb.data,0,sizeof(skb.data));skb.data[14]=0x45;skb.data[23]=17;
 pause_tag=true;tag_entered=continue_tag=drain_entered=hold_done=false;pthread_t receive,hold;
 T(pthread_create(&receive,NULL,receive_thread,&skb)==0);assert(pthread_mutex_lock(&rmu)==0);while(!tag_entered)pthread_cond_wait(&rcv,&rmu);assert(pthread_mutex_unlock(&rmu)==0);
 T(pthread_create(&hold,NULL,hold_thread,NULL)==0);assert(pthread_mutex_lock(&rmu)==0);while(!drain_entered)pthread_cond_wait(&rcv,&rmu);T(!hold_done&&active_readers>0);continue_tag=true;pthread_cond_broadcast(&rcv);assert(pthread_mutex_unlock(&rmu)==0);
 T(pthread_join(receive,NULL)==0&&pthread_join(hold,NULL)==0&&hold_result==0&&receive_result==-EPERM&&gta3xlwifi_netpolicy_held()&&active_readers==0);
 pause_tag=false;T(netpolicy_flush(&owner,NULL)==0);T(netpolicy_release(NULL,&owner)==0);lna_free(lna_current);lna_current=NULL;vfree(uid_image);uid_image=NULL;T(allocs==frees&&!rcu_depth&&!tag_depth);
 printf("passed_cases=%u negative_headroom_parser_comparisons=%u\n",cases,parse_comparisons);
}
'''
for name in ['gta3xlwifi_netpolicy.h','gta3xlwifi_uid_permissions.h']:
 src=a.store_host/'include/linux/netfilter'/name;dst=O/'include/linux/netfilter'/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes())
for src,dst in [(S/'include/uapi/linux/netfilter/gta3xlwifi_local_network.h',O/'include/linux/netfilter/gta3xlwifi_local_network.h'),(B/'include/net/gta3xlwifi_packet.h',O/'include/net/gta3xlwifi_packet.h')]:dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes())
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')];x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.fullmatch(r'passed_cases=(\d+) negative_headroom_parser_comparisons=(\d+)\n',x.stdout);assert match and int(match[1])>=40 and int(match[2])==5632
paths=[Path(__file__),helper,prior,a.store_host/'test.c',store,raw,internal,parser,filter,reference_filter,B/'net/core/dev.c',android,aids,pp,a.packet_host/'report.json',S/'include/net/gta3xlwifi_receive.h',O/'test.c'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'parser_headroom_comparisons':int(match[2]),'actual_socket_receive_hook_order_preserved':True,'real_mutex_HOLD_waits_for_receive_reader':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual receive/tag/filter/parser/store code, fatal UBSan fixtures')
