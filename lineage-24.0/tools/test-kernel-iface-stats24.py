#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual bounded interface store/snapshot and XT producer vs A17 counter macro.

Registration, skb, tag lookup and user copies are fixtures; real pthread locks
exercise snapshot/update concurrency. Actual A17 explicit interface4.9 arithmetic
is the oracle. No installed rules, UID accounting or whole-network readiness.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=S/'net/netfilter/gta3xlwifi_iface_stats.c';raw=S/'net/netfilter/xt_qtaguid.c';android=A/'packages/modules/Connectivity/bpf/progs/netd.c';at=android.read_text();rt=raw.read_text();header=S/'include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h';h=O/'include/linux/netfilter/gta3xlwifi_iface_stats.h';h.parent.mkdir(parents=True);h.write_bytes(header.read_bytes())
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
typedef uint32_t u32;typedef uint64_t u64;
#define __user
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define EXPORT_SYMBOL_GPL(x)
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define DEFINE_SPINLOCK(x) pthread_mutex_t x=PTHREAD_MUTEX_INITIALIZER
#define spin_lock_bh(x) assert(pthread_mutex_lock(x)==0)
#define spin_unlock_bh(x) assert(pthread_mutex_unlock(x)==0)
struct net{const void*user_ns;};struct sock{struct net*net;u32 uid;bool full;};
struct sk_buff{u32 len;uint16_t protocol;struct sock*sk;};
static u32 hash_32(u32 key,unsigned bits){return (key*0x9e370001U)>>(32-bits);}
static unsigned from_calls,to_calls,from_fault,to_fault,allocs,frees;static bool alloc_fault;static void(*copy_hook)(size_t);
static int copy_from_user(void*d,const void*s,size_t n){if(++from_calls==from_fault||!s)return 1;memcpy(d,s,n);return 0;}
static int copy_to_user(void*d,const void*s,size_t n){if(++to_calls==to_fault||!d)return 1;if(copy_hook)copy_hook(n);memcpy(d,s,n);return 0;}
static void*vzalloc(size_t n){if(alloc_fault)return NULL;void*p=calloc(1,n);if(p)++allocs;return p;}
static void vfree(void*p){if(p){++frees;free(p);}}
static void sort(void*p,size_t n,size_t size,int(*cmp)(const void*,const void*),void*swap){assert(!swap);qsort(p,n,size,cmp);}
u32 gta3xlwifi_iface_stats_features(void);
'''
code+=source.read_text()[source.read_text().index('#define IFACE_HASH_BITS'):source.read_text().index('MODULE_LICENSE(')]
code+=r'''
#define NF_INET_PRE_ROUTING 0
#define NF_INET_POST_ROUTING 4
#define NFPROTO_UNSPEC 0
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
struct net_device{u32 ifindex;};
struct xt_action_param{const void*matchinfo;const struct net_device*in,*out;};
struct xt_mtchk_param{const char*table;unsigned family,hook_mask;const void*matchinfo;};
struct xt_match{const char*name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void*me;};
static int init_user_ns,other_ns;static const void*user_ns=&init_user_ns;
static const void*current_user_ns(void){return user_ns;}
static struct sock*skb_to_full_sk(const struct sk_buff*s){return s->sk&&s->sk->full?s->sk:NULL;}
static bool sk_fullsock(const struct sock*s){return s->full;}
static struct net*sock_net(struct sock*s){return s->net;}
static u32 sock_net_uid(struct net*n,struct sock*s){assert(n==s->net);return s->uid;}
static u32 from_kuid_munged(const void*n,u32 uid){assert(n==&init_user_ns);return uid;}
static int metadata_result=-ENOENT;static u32 stats_uid,tag;static unsigned metadata_calls;
static int gta3xlwifi_socket_accounting(const struct sock*s,u32*u,u32*t){assert(s);++metadata_calls;if(metadata_result)return metadata_result;*u=stats_uid;*t=tag;return 0;}
static int reg_error;static unsigned registers;static int xt_register_match(struct xt_match*);
static bool gta3xlwifi_iface_registered;
'''
for name in ['gta3xlwifi_iface_stats_features','gta3xlwifi_iface_mt','gta3xlwifi_iface_check']:
 code+='\n'+m.extract(rt,name)+'\n'
begin=rt.index('static struct xt_match gta3xlwifi_iface_reg ');end=rt.index('module_init(gta3xlwifi_iface_init);',begin);code+=rt[begin:end]
code+=r'''
static int xt_register_match(struct xt_match*m){assert(m==&gta3xlwifi_iface_reg);++registers;return reg_error;}
#define function static
#define KVER_IS_AT_LEAST(k,a,b) ((k).version>=(((a)<<16)|((b)<<8)))
#define BPF_NOEXIST 1
struct kver_uint{unsigned version;};struct egress_bool{bool egress;};struct undo_bool{bool undo;};
struct bpf_sock{u32 protocol;};struct __sk_buff{u32 len;uint16_t protocol;u32 gso_segs;struct bpf_sock*sk;};
typedef struct{u64 rxPackets,rxBytes,txPackets,txBytes;}StatsValue;
static StatsValue oracle_value;
static StatsValue*bpf_iface_stats_map_lookup_elem(const u32*key){assert(!*key);return &oracle_value;}
static void bpf_iface_stats_map_update_elem(const u32*k,StatsValue*v,unsigned flags){(void)k;(void)v;assert(flags==BPF_NOEXIST);}
static struct bpf_sock*bpf_sk_fullsock(struct bpf_sock*s){return s;}
'''
begin=at.index('#define DEFINE_UPDATE_STATS(');end=at.index('DEFINE_UPDATE_STATS(app_uid_stats_map',begin);code+=at[begin:end]+'\nDEFINE_UPDATE_STATS(iface_stats_map,uint32_t)\n'
code+=r'''
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
static void reset_store(void){memset(iface_heads,0,sizeof(iface_heads));memset(iface_rows,0,sizeof(iface_rows));iface_count=0;iface_lost_updates=iface_sequence=0;from_calls=to_calls=from_fault=to_fault=0;alloc_fault=false;copy_hook=NULL;metadata_result=-ENOENT;metadata_calls=0;}
static long snap(struct gta3xlwifi_iface_stats_transfer*t){return gta3xlwifi_iface_stats_ioctl(GTA3XLWIFI_IFACE_STATS_GET,(unsigned long)t);}
static struct gta3xlwifi_iface_stats_transfer request(void*p,unsigned count){return(struct gta3xlwifi_iface_stats_transfer){1,count,(uintptr_t)p,0,0};}
static struct sk_buff packet={64,0,NULL};
static void*producer(void*arg){u32 id=(uintptr_t)arg;for(unsigned i=0;i<10000;i++)assert(gta3xlwifi_iface_account(&packet,id,i&1,false)==0);return NULL;}
static void during_copy(size_t n){if(n>sizeof(struct gta3xlwifi_iface_stats_transfer)){copy_hook=NULL;assert(gta3xlwifi_iface_account(&packet,17,true,false)==0);}}
int main(void){
 T(sizeof(struct gta3xlwifi_iface_stats_entry)==40&&sizeof(struct gta3xlwifi_iface_stats_transfer)==32&&GTA3XLWIFI_IFACE_STATS_GET==0xc020675a);
 T(gta3xlwifi_iface_stats_features()==0);struct gta3xlwifi_iface_stats_transfer t=request(NULL,0);T(snap(&t)==-EOPNOTSUPP);reg_error=-EIO;T(gta3xlwifi_iface_init()==-EIO&&gta3xlwifi_iface_stats_features()==0);reg_error=0;T(gta3xlwifi_iface_init()==0&&gta3xlwifi_iface_stats_features()==1024&&registers==2);
 for(u32 len=0;len<=65535;len++)for(unsigned family=0;family<3;family++)for(unsigned output=0;output<2;output++)for(unsigned undo=0;undo<2;undo++){
  struct sk_buff s={len,htons(family==0?ETH_P_IP:family==1?ETH_P_IPV6:0),NULL};u64 p,b;iface_amount(&s,&p,&b);if(undo){p=-p;b=-b;}memset(&oracle_value,0,sizeof(oracle_value));u32 key=0;struct __sk_buff os={len,s.protocol,300,NULL};update_iface_stats_map(&os,&key,(struct egress_bool){output},(struct kver_uint){(4<<16)|(9<<8)},(struct undo_bool){undo});assert(p==(output?oracle_value.txPackets:oracle_value.rxPackets)&&b==(output?oracle_value.txBytes:oracle_value.rxBytes));++comparisons;
 }
 reset_store();T(gta3xlwifi_iface_account(NULL,0,false,false)==-EINVAL);T(gta3xlwifi_iface_account(&packet,17,true,false)==0&&gta3xlwifi_iface_account(&packet,2,false,false)==0);struct gta3xlwifi_iface_stats_entry rows[1000];t=request(rows,1000);T(snap(&t)==0&&t.count==2&&t.update_sequence==2&&!t.lost_updates&&rows[0].ifindex==2&&rows[0].rx_packets==1&&rows[0].rx_bytes==64&&rows[1].ifindex==17&&rows[1].tx_packets==1&&!rows[1].reserved);
 t=request(NULL,0);T(snap(&t)==0&&t.count==2&&!t.entries);t=request(rows,1);T(snap(&t)==-ENOSPC&&t.count==1);T(gta3xlwifi_iface_account(&packet,17,true,true)==0);t=request(rows,1000);T(snap(&t)==0&&!rows[1].tx_packets&&!rows[1].tx_bytes);T(gta3xlwifi_iface_account(&packet,99,true,true)==0);t=request(rows,1000);T(snap(&t)==0&&rows[2].tx_packets==UINT64_MAX&&rows[2].tx_bytes==(u64)-64);
 for(unsigned fault=0;fault<5;fault++){t=request(rows,1000);if(fault==0)t.version=2;if(fault==1)t.count=1001;if(fault==2)t.entries=0;if(fault==3)t.lost_updates=1;if(fault==4)t.update_sequence=1;T(snap(&t)==-EINVAL);}
 t=request(rows,1000);from_fault=from_calls+1;T(snap(&t)==-EFAULT);from_fault=0;alloc_fault=true;T(snap(&t)==-ENOMEM);alloc_fault=false;
 for(unsigned copy=1;copy<=2;copy++){t=request(rows,1000);to_fault=to_calls+copy;T(snap(&t)==-EFAULT&&iface_count==3);to_fault=0;}
 t=request(rows,1000);copy_hook=during_copy;u64 before=iface_sequence;T(snap(&t)==0&&t.update_sequence==before&&iface_sequence==before+1&&rows[1].tx_packets==0);t=request(rows,1000);T(snap(&t)==0&&rows[1].tx_packets==1);
 reset_store();for(u32 id=1000;id>0;id--)assert(gta3xlwifi_iface_account(&packet,id,false,false)==0);T(gta3xlwifi_iface_account(&packet,1001,false,false)==-ENOSPC);t=request(rows,1000);T(snap(&t)==0&&t.count==1000&&t.lost_updates==1&&rows[0].ifindex==1&&rows[999].ifindex==1000);T(gta3xlwifi_iface_account(&packet,1,true,false)==0);gta3xlwifi_iface_lost();T(iface_lost_updates==2);iface_lost_updates=UINT64_MAX;gta3xlwifi_iface_lost();T(iface_lost_updates==UINT64_MAX);
 reset_store();pthread_t threads[8];for(unsigned i=0;i<8;i++)assert(pthread_create(&threads[i],NULL,producer,(void*)(uintptr_t)(i%4))==0);for(unsigned i=0;i<100;i++){t=request(rows,1000);assert(snap(&t)==0);for(unsigned j=0;j<t.count;j++)assert(rows[j].rx_bytes==rows[j].rx_packets*64&&rows[j].tx_bytes==rows[j].tx_packets*64);}for(unsigned i=0;i<8;i++)assert(pthread_join(threads[i],NULL)==0);t=request(rows,1000);T(snap(&t)==0&&t.count==4);for(unsigned i=0;i<4;i++)T(rows[i].rx_packets==10000&&rows[i].tx_packets==10000);
 reset_store();struct net net={&init_user_ns};struct sock sk={&net,1000,true};struct sk_buff frame={64,htons(ETH_P_IP),&sk};struct net_device dev={17};struct gta3xlwifi_iface_stats_match info={1,0};struct xt_action_param action={&info,NULL,&dev};metadata_result=0;stats_uid=1029;tag=0;T(!gta3xlwifi_iface_mt(&frame,&action)&&!iface_count);stats_uid=10001;T(gta3xlwifi_iface_mt(&frame,&action)&&iface_count==1);sk.uid=0;stats_uid=1029;unsigned lookups=metadata_calls;T(gta3xlwifi_iface_mt(&frame,&action)&&metadata_calls==lookups);sk.uid=1000;metadata_result=-EIO;u64 loss=iface_lost_updates;T(!gta3xlwifi_iface_mt(&frame,&action)&&iface_lost_updates==loss+1);metadata_result=-ENOENT;T(gta3xlwifi_iface_mt(&frame,&action));info.output=0;action.in=&dev;lookups=metadata_calls;T(gta3xlwifi_iface_mt(&frame,&action)&&metadata_calls==lookups);
 struct xt_mtchk_param check={"raw",NFPROTO_IPV4,1,&info};T(gta3xlwifi_iface_check(&check)==0);check.table="filter";T(gta3xlwifi_iface_check(&check)==-EINVAL);check.table="raw";check.hook_mask=16;T(gta3xlwifi_iface_check(&check)==-EINVAL);check.hook_mask=1;info.reserved=1;T(gta3xlwifi_iface_check(&check)==-EINVAL);info.reserved=0;info.output=2;T(gta3xlwifi_iface_check(&check)==-EINVAL);info.output=1;check.table="mangle";check.hook_mask=16;check.family=NFPROTO_IPV6;T(gta3xlwifi_iface_check(&check)==0);user_ns=&other_ns;T(gta3xlwifi_iface_check(&check)==-EINVAL);user_ns=&init_user_ns;
 T(allocs==frees);printf("passed_cases=%u actual_A17_amount_comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
r=re.fullmatch(r'passed_cases=(\d+) actual_A17_amount_comparisons=(\d+)\n',x.stdout);assert r and int(r[2])==786432
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,source,raw,header,android,O/'test.c',h]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(r[1]),'actual_A17_amount_comparisons':int(r[2]),'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
