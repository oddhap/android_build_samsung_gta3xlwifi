#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual bounded UID/tag/app store, banks, control/auth and A17 GSO oracle.

Socket/GSO, copies, credentials and packet entry are fixtures. Real pthread locks
exercise producer/flip/read/ACK concurrency. No actual packet hooks or global
readiness is installed or asserted by this storage primitive test.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess
from pathlib import Path
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
inc=O/'include/linux/netfilter';inc.mkdir(parents=True)
for f in (B/'include/uapi/linux/netfilter').glob('gta3xlwifi*.h'):shutil.copyfile(f,inc/f.name)
header=S/'include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h';shutil.copyfile(header,inc/header.name)
module=S/'net/netfilter/gta3xlwifi_packet_stats.c';driver=S/'net/netfilter/gta3xlwifi_netpolicy.c';android=A/'packages/modules/Connectivity/bpf/progs/netd.c';at=android.read_text()
assert 'uid_counterset_map, HASH, uint32_t, uint8_t, 20000' in at and 'app_uid_stats_map, HASH, uint32_t, StatsValue, 10000' in at
assert re.search(r'#define STATS_MAP_SIZE 5000\b',android.with_name('netd.h').read_text())
gso=B/'include/linux/skbuff.h';tcp=B/'net/ipv4/tcp_offload.c';assert re.search(r'unsigned short\s+gso_segs;',gso.read_text()) and 'gso_segs = NAPI_GRO_CB(skb)->count;' in tcp.read_text()
# Existing real lease credential/file/TGID checks are not changed by dispatch.
for name in ['netpolicy_privileged','netpolicy_open','netpolicy_drop_lease','netpolicy_flush','netpolicy_release']:
 assert m.extract(driver.read_text(),name)==m.extract((B/'net/netfilter/gta3xlwifi_netpolicy.c').read_text(),name)
code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
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
#include <linux/netfilter/gta3xlwifi_packet_stats.h>
#include <linux/netfilter/gta3xlwifi_uid_permissions.h>
#include <linux/netfilter/gta3xlwifi_local_network.h>
#include <linux/netfilter/gta3xlwifi_loopback.h>
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
typedef uint32_t u32;typedef uint64_t u64;
#define __user
#define EXPORT_SYMBOL_GPL(x)
#define CONFIG_INET 1
#define CONFIG_IPV6 1
#define READ_ONCE(x) (x)
#define DEFINE_SPINLOCK(x) pthread_mutex_t x=PTHREAD_MUTEX_INITIALIZER
#define spin_lock_bh(x) assert(pthread_mutex_lock(x)==0)
#define spin_unlock_bh(x) assert(pthread_mutex_unlock(x)==0)
struct sock{bool full;u32 sk_protocol;};
struct shared_info{unsigned short gso_segs;};
struct sk_buff{u32 len;uint16_t protocol;struct shared_info shared;};
static struct shared_info *skb_shinfo(const struct sk_buff*s){return (void*)&s->shared;}
static bool sk_fullsock(const struct sock*s){return s->full;}
static u32 hash_32(u32 key,unsigned bits){return (key*0x9e370001U)>>(32-bits);}
static unsigned from_calls,to_calls,from_fault,to_fault,allocs,frees;static bool alloc_fault;
static void(*copy_hook)(void*,const void*,size_t);
static int copy_from_user(void*d,const void*s,size_t n){if(++from_calls==from_fault||!s)return 1;memcpy(d,s,n);return 0;}
static int copy_to_user(void*d,const void*s,size_t n){if(++to_calls==to_fault||!d)return 1;if(copy_hook)copy_hook(d,s,n);memcpy(d,s,n);return 0;}
static void*vzalloc(size_t n){if(alloc_fault)return NULL;void*p=calloc(1,n);if(p)++allocs;return p;}
static void vfree(void*p){if(p){++frees;free(p);}}
static void sort(void*p,size_t n,size_t size,int(*cmp)(const void*,const void*),void*swap){assert(!swap);qsort(p,n,size,cmp);}
'''
text=module.read_text();code+=text[text.index('#define STATS_HASH_BITS'):text.index('MODULE_LICENSE(')]
code+=r'''
struct file{int id;};struct pid{int id;};
static struct file owner={1},other_file={2};static struct pid owner_pid={1},other_pid={2};
static struct file*netpolicy_owner_file=&owner;static struct pid*netpolicy_owner_pid=&owner_pid,*fixture_pid=&owner_pid;
static bool privileged=true,netpolicy_held=true;
static void*current;
static struct pid*task_tgid(void*p){assert(p==current);return fixture_pid;}
static bool netpolicy_privileged(void){return privileged;}
static pthread_mutex_t netpolicy_lock=PTHREAD_MUTEX_INITIALIZER;
#define mutex_lock(x) assert(pthread_mutex_lock(x)==0)
#define mutex_unlock(x) assert(pthread_mutex_unlock(x)==0)
static u32 gta3xlwifi_uid_permissions_features(void){return 0;}
static u32 gta3xlwifi_lna_packet_features(void){return 0;}
static u32 gta3xlwifi_receive_features(void){return 0;}
static u32 gta3xlwifi_egress_features(void){return 0;}
static u32 gta3xlwifi_loopback_features(void){return 0;}
static u32 gta3xlwifi_socket_tables_features(void){return 0;}
static u32 gta3xlwifi_iface_stats_features(void){return 0;}
static long gta3xlwifi_iface_stats_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"unrelated interface fixture");return -ENOTTY;}
static long gta3xlwifi_loopback_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"unrelated loopback fixture");return -ENOTTY;}
static long gta3xlwifi_lna_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"unrelated LNA fixture");return -ENOTTY;}
static long gta3xlwifi_uid_permissions_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"unrelated permissions fixture");return -ENOTTY;}
'''+m.extract(driver.read_text(),'netpolicy_image_ioctl')+r'''
#define function static
#define KVER_IS_AT_LEAST(k,a,b) ((k).version>=(((a)<<16)|((b)<<8)))
#define BPF_NOEXIST 1
struct kver_uint{unsigned version;};struct egress_bool{bool egress;};struct undo_bool{bool undo;};
struct bpf_sock{u32 protocol;bool full;};struct __sk_buff{u32 len;uint16_t protocol;u32 gso_segs;struct bpf_sock*sk;};
typedef struct{u64 rxPackets,rxBytes,txPackets,txBytes;}StatsValue;
static StatsValue oracle_value;
static StatsValue*bpf_app_uid_stats_map_lookup_elem(const u32*key){assert(!*key);return &oracle_value;}
static void bpf_app_uid_stats_map_update_elem(const u32*k,StatsValue*v,unsigned flags){(void)k;(void)v;assert(flags==BPF_NOEXIST);}
static struct bpf_sock*bpf_sk_fullsock(struct bpf_sock*s){return s->full?s:NULL;}
'''
begin=at.index('#define DEFINE_UPDATE_STATS(');end=at.index('DEFINE_UPDATE_STATS(app_uid_stats_map',begin);code+=at[begin:end]+'\nDEFINE_UPDATE_STATS(app_uid_stats_map,uint32_t)\n'
code+=r'''
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
static void reset_store(void){
 assert(allocs==frees);memset(stats_banks,0,sizeof(stats_banks));stats_bank_epoch[0]=1;stats_bank_epoch[1]=0;stats_active=0;stats_epoch=1;stats_total_lost=0;memset(app_heads,0,sizeof(app_heads));memset(app_rows,0,sizeof(app_rows));app_count=0;app_lost=app_sequence=0;memset(set_heads,0,sizeof(set_heads));memset(set_rows,0,sizeof(set_rows));set_count=set_cursor=set_free=0;from_calls=to_calls=from_fault=to_fault=0;alloc_fault=false;copy_hook=NULL;netpolicy_owner_file=&owner;netpolicy_owner_pid=fixture_pid=&owner_pid;privileged=true;netpolicy_held=true;
}
static long io(unsigned cmd,void*p){return netpolicy_image_ioctl(&owner,cmd,(unsigned long)p);}
static struct gta3xlwifi_packet_stats_state state(void){struct gta3xlwifi_packet_stats_state s;memset(&s,0xff,sizeof(s));assert(io(GTA3XLWIFI_STATS_GET_STATE,&s)==0);return s;}
static struct gta3xlwifi_packet_stats_swap flip(void){struct gta3xlwifi_packet_stats_state s=state();struct gta3xlwifi_packet_stats_swap q={1,s.active_bank,s.active_epoch,0,0,0};assert(io(GTA3XLWIFI_STATS_SWAP,&q)==0);return q;}
static long ack(u32 bank,u64 epoch){struct gta3xlwifi_packet_stats_ack q={1,bank,epoch,0};return io(GTA3XLWIFI_STATS_ACK,&q);}
static long edit(u32 op,u32 uid,u32 value){struct gta3xlwifi_packet_stats_edit q={1,op,uid,0,value,0};return io(GTA3XLWIFI_STATS_EDIT,&q);}
static struct gta3xlwifi_packet_stats_transfer req(u32 kind,u64 epoch,void*rows,u32 count){return(struct gta3xlwifi_packet_stats_transfer){1,kind,epoch,count,0,(uintptr_t)rows,0,0};}
static struct sk_buff packet={64,0,{1}};
static struct gta3xlwifi_packet_stats_entry wire[5000];static struct gta3xlwifi_app_stats_entry apps[10000];
static void*producer(void*p){u32 uid=(uintptr_t)p;for(unsigned i=0;i<10000;i++)assert(!gta3xlwifi_packet_stats_record(NULL,&packet,uid,i&1,17,i&1));return NULL;}
static u64 collected[9];
static void drain(void){struct gta3xlwifi_packet_stats_swap f=flip();struct gta3xlwifi_packet_stats_transfer q=req(f.inactive_bank,f.inactive_epoch,wire,5000);assert(!io(GTA3XLWIFI_STATS_READ,&q));for(u32 i=0;i<q.count;i++){assert(wire[i].key.uid<9);collected[wire[i].key.uid]+=wire[i].rx_packets+wire[i].tx_packets;}assert(!q.lost_updates&&ack(f.inactive_bank,f.inactive_epoch)==0&&ack(f.inactive_bank,f.inactive_epoch)==0);}
static void record_during_copy(void*d,const void*s,size_t n){(void)s;(void)n;if(d==wire){copy_hook=NULL;assert(!gta3xlwifi_packet_stats_record(NULL,&packet,20002,7,17,true));}}
int main(void){
 T(sizeof(struct gta3xlwifi_stats_key)==16&&sizeof(struct gta3xlwifi_packet_stats_entry)==48&&sizeof(struct gta3xlwifi_app_stats_entry)==40);
 T(sizeof(struct gta3xlwifi_packet_stats_state)==88&&sizeof(struct gta3xlwifi_packet_stats_transfer)==48&&sizeof(struct gta3xlwifi_packet_stats_swap)==32&&sizeof(struct gta3xlwifi_packet_stats_ack)==24&&sizeof(struct gta3xlwifi_packet_stats_edit)==24);
 T(GTA3XLWIFI_STATS_GET_STATE==0x8058675b&&GTA3XLWIFI_STATS_READ==0xc030675c&&GTA3XLWIFI_STATS_SWAP==0xc020675d&&GTA3XLWIFI_STATS_ACK==0x4018675e&&GTA3XLWIFI_STATS_EDIT==0x4018675f);
 T(gta3xlwifi_packet_stats_features()==4096);reset_store();struct gta3xlwifi_packet_stats_state s=state();T(s.version==1&&!s.active_bank&&s.active_epoch==1&&s.bank_epoch[0]==1&&!s.pending_mask&&!s.reserved&&!s.app_count);
 const unsigned segments[]={0,1,2,64,65535};
 for(u32 len=0;len<65536;len++)for(unsigned family=0;family<3;family++)for(unsigned seg=0;seg<5;seg++)for(unsigned kind=0;kind<5;kind++)for(unsigned output=0;output<2;output++){
  struct sock sk={kind!=1,kind==2?IPPROTO_TCP:kind==3?IPPROTO_UDP:IPPROTO_GRE};struct sk_buff frame={len,htons(family==0?ETH_P_IP:family==1?ETH_P_IPV6:0),{segments[seg]}};struct bpf_sock osk={sk.sk_protocol,sk.full};struct __sk_buff oracle={len,frame.protocol,segments[seg],kind?&osk:NULL};u64 packets,bytes;packet_amount(kind?&sk:NULL,&frame,&packets,&bytes);memset(&oracle_value,0,sizeof(oracle_value));u32 key=0;update_app_uid_stats_map(&oracle,&key,(struct egress_bool){output},(struct kver_uint){(5<<16)|(4<<8)},(struct undo_bool){false});assert(packets==(output?oracle_value.txPackets:oracle_value.rxPackets)&&bytes==(output?oracle_value.txBytes:oracle_value.rxBytes));++comparisons;
 }
 T(gta3xlwifi_packet_stats_record(NULL,NULL,0,0,0,false)==-EINVAL);
 reset_store();T(edit(GTA3XLWIFI_STATS_SET_COUNTERSET,3,1)==0);T(!gta3xlwifi_packet_stats_record(NULL,&packet,3,2,17,true));T(!gta3xlwifi_packet_stats_record(NULL,&packet,1,0,2,false));T(!gta3xlwifi_packet_stats_record(NULL,&packet,3,1,4,true));struct gta3xlwifi_packet_stats_swap f=flip();struct gta3xlwifi_packet_stats_transfer q=req(f.inactive_bank,f.inactive_epoch,wire,5000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==3&&wire[0].key.uid==1&&wire[1].key.tag==1&&wire[2].key.counterset==1&&wire[2].tx_bytes==64);
 T(edit(GTA3XLWIFI_STATS_DELETE_UID,3,0)==-EBUSY);struct gta3xlwifi_packet_stats_swap stale={1,0,1,0,0,0};T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-ESTALE);stale=(struct gta3xlwifi_packet_stats_swap){1,1,2,0,0,0};T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-EBUSY);
 q=req(f.inactive_bank,f.inactive_epoch,NULL,0);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==3&&!q.entries);q=req(f.inactive_bank,f.inactive_epoch,wire,1);T(io(GTA3XLWIFI_STATS_READ,&q)==-ENOSPC&&q.count==1);q=req(f.inactive_bank,f.inactive_epoch+1,wire,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-ESTALE);q=req(1,2,wire,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-EBUSY);
 q=req(2,0,apps,10000);memset(apps,0xff,sizeof(apps));T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==2&&apps[0].uid==1&&apps[1].uid==3&&!apps[1].reserved&&apps[1].tx_packets==2);
 T(ack(f.inactive_bank,f.inactive_epoch)==0&&ack(f.inactive_bank,f.inactive_epoch)==0);q=req(f.inactive_bank,f.inactive_epoch,wire,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-ENODATA);T(edit(GTA3XLWIFI_STATS_DELETE_UID,3,0)==0&&app_count==1&&set_count==0);
 reset_store();gta3xlwifi_packet_stats_record(NULL,&packet,1,0,17,true);to_fault=to_calls+1;stale=(struct gta3xlwifi_packet_stats_swap){1,0,1,0,0,0};T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-EFAULT);to_fault=0;s=state();T(s.active_bank==1&&s.active_epoch==2&&s.pending_mask==1&&s.bank_count[0]==1);T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-ESTALE);T(!gta3xlwifi_packet_stats_record(NULL,&packet,2,0,17,true));T(ack(0,1)==0);f=flip();T(f.active_bank==0&&f.active_epoch==3&&f.inactive_bank==1&&f.inactive_epoch==2);gta3xlwifi_packet_stats_record(NULL,&packet,3,0,17,true);T(ack(0,1)==0&&stats_banks[0].count==1);T(ack(0,3)==-ESTALE);T(ack(1,2)==0);
 reset_store();gta3xlwifi_packet_stats_record(NULL,&packet,1,0,17,true);f=flip();for(unsigned fault=0;fault<8;fault++){q=req(f.inactive_bank,f.inactive_epoch,wire,5000);switch(fault){case 0:q.version=2;break;case 1:q.kind=3;break;case 2:q.reserved=1;break;case 3:q.lost_updates=1;break;case 4:q.sequence=1;break;case 5:q.count=5001;break;case 6:q.entries=0;break;case 7:q.count=0;break;}T(io(GTA3XLWIFI_STATS_READ,&q)==-EINVAL&&stats_banks[0].count==1&&stats_banks[0].pending);}
 q=req(2,1,apps,10000);T(io(GTA3XLWIFI_STATS_READ,&q)==-EINVAL);q=req(2,0,apps,10000);alloc_fault=true;T(io(GTA3XLWIFI_STATS_READ,&q)==-ENOMEM);alloc_fault=false;
 q=req(0,1,wire,5000);from_fault=from_calls+1;T(io(GTA3XLWIFI_STATS_READ,&q)==-EFAULT);from_fault=0;for(unsigned n=1;n<=2;n++){q=req(0,1,wire,5000);to_fault=to_calls+n;T(io(GTA3XLWIFI_STATS_READ,&q)==-EFAULT&&stats_banks[0].pending&&stats_banks[0].count==1);to_fault=0;}
 q=req(0,1,wire,5000);copy_hook=record_during_copy;T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==1&&wire[0].key.uid==1&&stats_banks[1].count==1&&app_count==2);T(ack(0,1)==0);
 reset_store();for(u32 tag=0;tag<5000;tag++)assert(!gta3xlwifi_packet_stats_record(NULL,&packet,7,tag,17,true));T(gta3xlwifi_packet_stats_record(NULL,&packet,7,5000,17,true)==-ENOSPC);T(stats_banks[0].lost==1&&stats_total_lost==1&&app_count==1&&app_rows[0].entry.tx_packets==5001&&!app_lost);T(!gta3xlwifi_packet_stats_record(NULL,&packet,7,0,17,true));stats_banks[0].lost=stats_total_lost=app_lost=UINT64_MAX;gta3xlwifi_packet_stats_lost();T(stats_banks[0].lost==UINT64_MAX&&stats_total_lost==UINT64_MAX&&app_lost==UINT64_MAX);
 reset_store();for(u32 uid=0;uid<10000;uid++){assert(!gta3xlwifi_packet_stats_record(NULL,&packet,uid,0,17,true));if((uid+1)%5000==0){f=flip();assert(!ack(f.inactive_bank,f.inactive_epoch));}}T(app_count==10000);T(gta3xlwifi_packet_stats_record(NULL,&packet,10000,0,17,true)==-ENOSPC&&app_lost==1&&!stats_banks[stats_active].lost&&stats_banks[stats_active].count==1);T(!gta3xlwifi_packet_stats_record(NULL,&packet,1,0,17,true));T(edit(GTA3XLWIFI_STATS_DELETE_UID,4000,0)==0&&app_count==9999&&app_lost==1);T(!gta3xlwifi_packet_stats_record(NULL,&packet,10000,0,17,true)&&app_count==10000);q=req(2,0,apps,10000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&apps[9999].uid==10000&&apps[9999].tx_packets==1&&!apps[9999].reserved&&q.lost_updates==1);
 reset_store();for(u32 uid=0;uid<20000;uid++)assert(!edit(GTA3XLWIFI_STATS_SET_COUNTERSET,uid,1));T(set_count==20000&&edit(GTA3XLWIFI_STATS_SET_COUNTERSET,20000,1)==-ENOSPC);T(edit(GTA3XLWIFI_STATS_SET_COUNTERSET,123,0)==0&&edit(GTA3XLWIFI_STATS_SET_COUNTERSET,20000,1)==0&&set_count==20000&&set_cursor==20000);T(!gta3xlwifi_packet_stats_record(NULL,&packet,123,0,17,true)&&!gta3xlwifi_packet_stats_record(NULL,&packet,20000,0,17,true)&&stats_banks[0].rows[0].entry.key.counterset==0&&stats_banks[0].rows[1].entry.key.counterset==1);T(edit(GTA3XLWIFI_STATS_SET_COUNTERSET,5,2)==-EINVAL);
 reset_store();gta3xlwifi_packet_stats_record(NULL,&packet,UINT32_MAX,UINT32_MAX,UINT32_MAX,true);stats_banks[0].rows[0].entry.tx_packets=app_rows[0].entry.tx_packets=UINT64_MAX;stats_banks[0].rows[0].entry.tx_bytes=app_rows[0].entry.tx_bytes=UINT64_MAX;stats_banks[0].sequence=app_sequence=UINT64_MAX;T(!gta3xlwifi_packet_stats_record(NULL,&packet,UINT32_MAX,UINT32_MAX,UINT32_MAX,true)&&!stats_banks[0].rows[0].entry.tx_packets&&stats_banks[0].rows[0].entry.tx_bytes==63&&!app_rows[0].entry.tx_packets&&!app_sequence&&!stats_banks[0].sequence);
 reset_store();stats_epoch=stats_bank_epoch[0]=UINT64_MAX;stale=(struct gta3xlwifi_packet_stats_swap){1,0,UINT64_MAX,0,0,0};T(io(GTA3XLWIFI_STATS_SWAP,&stale)==-EOVERFLOW&&stats_active==0&&!stats_banks[0].pending);
 reset_store();const unsigned cmds[]={GTA3XLWIFI_STATS_GET_STATE,GTA3XLWIFI_STATS_READ,GTA3XLWIFI_STATS_SWAP,GTA3XLWIFI_STATS_ACK,GTA3XLWIFI_STATS_EDIT};unsigned char storage[128]={0};
 for(unsigned n=0;n<5;n++){privileged=false;T(io(cmds[n],storage)==-EPERM);privileged=true;fixture_pid=&other_pid;T(io(cmds[n],storage)==-EPERM);fixture_pid=&owner_pid;T(netpolicy_image_ioctl(&other_file,cmds[n],(unsigned long)storage)==-EPERM);netpolicy_owner_file=NULL;T(io(cmds[n],storage)==-ENOTCONN);netpolicy_owner_file=&owner;T(io(cmds[n],NULL)==-EFAULT);}
 T((netpolicy_image_ioctl(&owner,GTA3XLWIFI_UID_FEATURES,0)&4096)==4096);netpolicy_held=false;T(edit(GTA3XLWIFI_STATS_SET_COUNTERSET,1,1)==0);f=flip();T(ack(f.inactive_bank,f.inactive_epoch)==0);T(gta3xlwifi_packet_stats_ioctl(0,(unsigned long)&s)==-ENOTTY);
 reset_store();memset(collected,0,sizeof(collected));pthread_t threads[8];for(uintptr_t n=1;n<=8;n++)assert(!pthread_create(&threads[n-1],NULL,producer,(void*)n));for(unsigned n=0;n<100;n++)drain();for(unsigned n=0;n<8;n++)assert(!pthread_join(threads[n],NULL));drain();for(unsigned n=1;n<=8;n++)T(collected[n]==10000);q=req(2,0,apps,10000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==8&&!q.lost_updates);for(unsigned n=0;n<8;n++)T(apps[n].rx_packets+apps[n].tx_packets==10000);T(!stats_total_lost&&allocs==frees);
 printf("passed_cases=%u comparisons=%u concurrent_updates=80000\n",cases,comparisons);
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=180,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);result=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+) concurrent_updates=80000\n',x.stdout);assert result and int(result[2])==9830400
paths=[Path(__file__),helper,module,driver,header,android,android.with_name('netd.h'),gso,tcp,O/'test.c',*[p for p in inc.glob('*.h')]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(result[1]),'actual_A17_GSO_comparisons':int(result[2]),'concurrent_updates':80000,'credential_file_TGID_auth_exercised':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'packet_hooks_installed':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
