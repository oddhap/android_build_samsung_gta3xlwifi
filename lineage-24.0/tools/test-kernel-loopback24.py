#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual loopback permission/egress/event queue/lease dispatch with host fixtures.

Peer lookup is a referenced-lookup result fixture (that helper has separate tests).
Actual A17 permission expressions are compiled as oracle. RCU/copies/credentials/
clock/sockets are modeled; no real packets, hardware or whole-backend readiness.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-kernel','store-host','packet-host','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
egress=Path(__file__).with_name('test-kernel-egress-context24.py');cmd=['python3',str(egress)]
for n in ['source','base-kernel','store-host','packet-host','android-source']:cmd+=['--'+n,str(getattr(a,n.replace('-','_')))]
cmd+=['--output',str(O/'egress-regression')];subprocess.run(cmd,check=True)
prior=O/'egress-regression/test.c';code=prior.read_text().replace('int main(void){','static int egress_regression_main(void){')
stub=m.extract(code,'gta3xlwifi_loopback_blocked');code=code.replace(stub,'bool gta3xlwifi_loopback_blocked(struct net*,u32,u32,const struct gta3xlwifi_packet*);')
code=code.replace('static int copy_to_user(', 'static void (*copy_hook)(void*,const void*,size_t);\nstatic int copy_to_user(').replace('static int copy_to_user(void*d,const void*s,size_t n){','static int copy_to_user(void*d,const void*s,size_t n){if(copy_hook)copy_hook(d,s,n);')
header=S/'include/uapi/linux/netfilter/gta3xlwifi_loopback.h';dst=O/'egress-regression/receive-prerequisite/include/linux/netfilter/gta3xlwifi_loopback.h';dst.write_bytes(header.read_bytes());code='#include <linux/netfilter/gta3xlwifi_loopback.h>\n'+code
# Compile the actual extended owner dispatch, not the hash-bound prior store's old dispatch.
driver=S/'net/netfilter/gta3xlwifi_netpolicy.c';d=driver.read_text();i=code.index(m.extract(code,'netpolicy_image_ioctl'));code=code[:i]+'u32 gta3xlwifi_receive_features(void);u32 gta3xlwifi_egress_features(void);u32 gta3xlwifi_loopback_features(void);long gta3xlwifi_loopback_ioctl(unsigned int,unsigned long);\n'+code[i:]
if 'gta3xlwifi_socket_tables_features()' in d:
 code='static unsigned gta3xlwifi_socket_tables_features(void){return 0;} /* table lifecycle tested separately */\n'+code
iface_header=S/'include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h'
if iface_header.exists():
 dst=O/'egress-regression/receive-prerequisite/include/linux/netfilter/gta3xlwifi_iface_stats.h';dst.write_bytes(iface_header.read_bytes())
 code='#include <linux/netfilter/gta3xlwifi_iface_stats.h>\nstatic unsigned gta3xlwifi_iface_stats_features(void){return 0;} /* separately tested counter producer */\nstatic long gta3xlwifi_iface_stats_ioctl(unsigned int c,unsigned long a){(void)c;(void)a;return -25;}\n'+code
packet_header=S/'include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h'
if packet_header.exists():
 dst=O/'egress-regression/receive-prerequisite/include/linux/netfilter/gta3xlwifi_packet_stats.h';dst.write_bytes(packet_header.read_bytes())
 code='#include <linux/netfilter/gta3xlwifi_packet_stats.h>\nstatic unsigned gta3xlwifi_packet_stats_features(void){return 0;} /* separately tested packet storage */\nstatic long gta3xlwifi_packet_stats_ioctl(unsigned int c,unsigned long a){(void)c;(void)a;return -25;}\n'+code
if 'gta3xlwifi_packet_hooks_features()' in d:
 code='static unsigned gta3xlwifi_packet_hooks_features(void){return 0;} /* compiled producer admission separately tested */\n'+code
runtime_header=S/'include/uapi/linux/netfilter/gta3xlwifi_runtime_policy.h'
if runtime_header.exists():
 dst=O/'egress-regression/receive-prerequisite/include/linux/netfilter/gta3xlwifi_runtime_policy.h';dst.write_bytes(runtime_header.read_bytes())
 code='#include <stdbool.h>\n#include <linux/netfilter/gta3xlwifi_runtime_policy.h>\nstatic unsigned gta3xlwifi_runtime_features(void){return 0;}\nstatic bool gta3xlwifi_runtime_configured(void){return true;}\nstatic unsigned gta3xlwifi_runtime_loopback_flags(void){return 3;} /* explicit checks+metrics fixture */\nstatic long gta3xlwifi_runtime_ioctl(unsigned c,unsigned long a){(void)c;(void)a;return -25;}\n'+code
for name in ['netpolicy_image_ioctl','netpolicy_ioctl']:code=code.replace(m.extract(code,name),m.extract(d,name))
peer=S/'include/net/gta3xlwifi_socket_peer.h';dst=O/'egress-regression/receive-prerequisite/include/net/gta3xlwifi_socket_peer.h';dst.write_bytes(peer.read_bytes())
code+=r'''
#include <net/gta3xlwifi_socket_peer.h>
#define DEFINE_SPINLOCK(name) pthread_mutex_t name=PTHREAD_MUTEX_INITIALIZER
static u64 mock_boottime;
static u64 ktime_get_boot_ns(void){return mock_boottime;}
static bool peer_known;static u32 peer_uid;static unsigned peer_lookups;
static struct gta3xlwifi_socket_peer_tuple last_tuple;
static bool gta3xlwifi_socket_peer_uid(struct net*n,int ifindex,const struct gta3xlwifi_socket_peer_tuple*t,u32*uid){assert(n==&net&&ifindex==1&&rcu_depth);++peer_lookups;last_tuple=*t;if(!peer_known)return false;*uid=peer_uid;return true;}
'''
# Header declares a global function; fixture implements that exact declaration.
code=code.replace('static bool gta3xlwifi_socket_peer_uid(', 'bool gta3xlwifi_socket_peer_uid(')
source=S/'net/netfilter/gta3xlwifi_loopback.c';text=source.read_text();code+='\n'+text[text.index('#define LOOPBACK_CACHE_SIZE'):text.index('MODULE_LICENSE(')]
android=A/'packages/modules/Connectivity/bpf/progs/netd.c';ah=android.with_name('netd.h');at=android.read_text();ht=ah.read_text()
start=ht.index('enum LoopbackAccessResult : uint32_t {');end=ht.index('};',start)+2
code+='\n'+ht[start:end].replace(' : uint32_t','')+'\n_Static_assert(LOOPBACK_ACCESS_ALLOWED==GTA3XLWIFI_LOOPBACK_ALLOWED,"A17 allowed payload");\n_Static_assert(LOOPBACK_ACCESS_BLOCKED==GTA3XLWIFI_LOOPBACK_BLOCKED,"A17 blocked payload");\n'
for macro in ['FORCE_USE_LOOPBACK_INTERFACE','INTERACT_ACROSS_USERS_FULL','INTERACT_ACROSS_USERS_OR_PROFILES']:
 line=next(l for l in ht.splitlines() if l.startswith('#define PERMISSION_BIT_'+macro+' '));code+='\n'+line
code+='\n'+m.extract(at,'can_force_loopback')+'\n'+m.extract(at,'uids_have_loopback_permissions')
code+=r'''
static void clear_events(void){memset(loopback_cache,0,sizeof(loopback_cache));memset(loopback_events,0,sizeof(loopback_events));loopback_head=loopback_count=0;loopback_sequence=loopback_losses=loopback_recency=0;mock_boottime=1000000000ULL;}
static long event_io(struct gta3xlwifi_loopback_transfer*t){return netpolicy_ioctl(&owner,GTA3XLWIFI_LOOPBACK_GET_EVENTS,(unsigned long)t);}
static void install_permissions(u32 a,u32 b,u32 pa,u32 pb){
 T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0);
 struct gta3xlwifi_uid_permission_entry entries[2];unsigned count=0;
 if(pa){entries[count++]=(struct gta3xlwifi_uid_permission_entry){a,pa};}if(pb&&a!=b){entries[count++]=(struct gta3xlwifi_uid_permission_entry){b,pb};}
 if(count==2&&entries[0].uid>entries[1].uid){struct gta3xlwifi_uid_permission_entry x=entries[0];entries[0]=entries[1];entries[1]=x;}
 struct gta3xlwifi_uid_permission_transfer t={1,count,uid_image?uid_image->revision+1:1,count?(uintptr_t)entries:0};T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
}
static pthread_mutex_t copy_mu=PTHREAD_MUTEX_INITIALIZER;static pthread_cond_t copy_cv=PTHREAD_COND_INITIALIZER;static bool copy_started,copy_continue;static int consume_result;static struct gta3xlwifi_loopback_transfer consume_transfer;
static void pause_copy(void*d,const void*s,size_t n){(void)d;(void)s;if(n!=sizeof(struct gta3xlwifi_loopback_event))return;assert(pthread_mutex_lock(&copy_mu)==0);copy_started=true;pthread_cond_broadcast(&copy_cv);while(!copy_continue)pthread_cond_wait(&copy_cv,&copy_mu);assert(pthread_mutex_unlock(&copy_mu)==0);}
static void*consume_thread(void*x){(void)x;consume_result=event_io(&consume_transfer);return NULL;}
static unsigned permission_comparisons;
int main(void){
 assert(egress_regression_main()==0);unsigned before_cases=cases;T(gta3xlwifi_loopback_features()==128);T(netpolicy_open(NULL,&owner)==0);T(netpolicy_ioctl(&owner,GTA3XLWIFI_UID_FEATURES,0)==239);
 struct gta3xlwifi_lna_transfer lna={1,0,0,0,1,0,0};T(io(GTA3XLWIFI_LNA_SET_IMAGE,&lna)==0);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
 // Exhaust all seven-bit permission pairs against actual A17 expressions.
 const u32 pairs[][2]={{10001,110001},{10001,110002},{65534,110001},{110001,65534},{1000,110001},{10001,10002}};
 for(unsigned pair=0;pair<6;pair++)for(unsigned a=0;a<128;a++)for(unsigned b=0;b<128;b++){
  struct gta3xlwifi_uid_permission_entry entries[2]={{pairs[pair][0],a},{pairs[pair][1],b}};if(entries[0].uid>entries[1].uid){struct gta3xlwifi_uid_permission_entry x=entries[0];entries[0]=entries[1];entries[1]=x;}
  // Direct actual image for this pure expression oracle, never a runtime input API.
  struct gta3xlwifi_uid_image *image=calloc(1,sizeof(*image)+2*sizeof(entries[0]));assert(image);image->count=2;memcpy(image->entries,entries,sizeof(entries));struct gta3xlwifi_uid_image*old=uid_image;uid_image=image;
  assert(loopback_permissions(pairs[pair][0],pairs[pair][1])==uids_have_loopback_permissions(pairs[pair][0],pairs[pair][1]));++permission_comparisons;uid_image=old;free(image);
 }
 install_permissions(10001,110001,0,0);clear_events();peer_known=true;peer_uid=110001;device.ifindex=1;receiver.uid=10001;receiver.sk_family=AF_INET;receiver.full=true;tagged_sk=NULL;
 struct sk_buff skb={.length=1166,.data_at=34,.network=-20,.protocol=htons(ETH_P_IP),.sk=&foreign,.dev=&device};skb.data[14]=0x45;skb.data[23]=17;skb.data[26]=127;skb.data[29]=1;skb.data[30]=127;skb.data[33]=1;skb.data[34]=0x12;skb.data[35]=0x34;skb.data[36]=0x56;skb.data[37]=0x78;
 T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==1&&last_tuple.family==AF_INET&&last_tuple.protocol==17&&last_tuple.sport==htons(0x1234)&&last_tuple.dport==htons(0x5678));
 struct gta3xlwifi_loopback_transfer transfer={1,0,0,0,0};T(event_io(&transfer)==0&&transfer.count==1&&transfer.first_sequence==1&&transfer.lost_events==0);
 struct gta3xlwifi_loopback_event events[512];transfer.entries=(uintptr_t)events;T(event_io(&transfer)==0&&transfer.count==1&&loopback_count==0);T(events[0].sender_uid==10001&&events[0].receiver_uid==110001&&events[0].result==1&&events[0].reserved==0&&events[0].boottime_ns==mock_boottime&&events[0].sequence==1);
 mock_boottime+=59000000000ULL;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==0);mock_boottime+=1000000000ULL;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==1);
 install_permissions(10001,110001,64,0);T(gta3xlwifi_egress_policy(&receiver,&skb)==0&&loopback_count==2&&loopback_events[(loopback_head+1)%512].result==0);install_permissions(10001,110001,0,0);
 clear_events();peer_known=false;unsigned before_lookup=peer_lookups;T(gta3xlwifi_egress_policy(&receiver,&skb)==0&&loopback_count==0&&peer_lookups==before_lookup+1);peer_known=true;peer_uid=10001;T(gta3xlwifi_egress_policy(&receiver,&skb)==0&&loopback_count==0);peer_uid=110001;
 // TCP ACK skips lookup; SYN and SYN+ACK are checked; other protocols skip.
 skb.data[23]=6;skb.data[47]=16;before_lookup=peer_lookups;T(gta3xlwifi_egress_policy(&receiver,&skb)==0&&peer_lookups==before_lookup);skb.data[47]=2;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&peer_lookups==before_lookup+1);skb.data[47]=18;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);skb.data[23]=132;before_lookup=peer_lookups;T(gta3xlwifi_egress_policy(&receiver,&skb)==0&&peer_lookups==before_lookup);skb.data[23]=17;
 // DNS bypass is LNA-only. Tagged and untagged CLAT bypass loopback before parse.
 clear_events();tagged_sk=&receiver;tagged.tag=((u64)0xffffff82<<32)|1051;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==1);tagged.tag=1029;before_lookup=peer_lookups;T(gta3xlwifi_egress_policy(&receiver,&skb)==0&&peer_lookups==before_lookup&&loopback_count==1);tagged_sk=NULL;receiver.uid=1029;T(gta3xlwifi_egress_policy(&receiver,&skb)==0&&peer_lookups==before_lookup);receiver.uid=65534;T(gta3xlwifi_egress_policy(&receiver,&skb)==0&&loopback_events[(loopback_head+1)%512].sender_uid==0);receiver.uid=110001;peer_uid=65534;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_events[(loopback_head+2)%512].receiver_uid==65534);
 // IPv6 parser -> exact referenced tuple and actual receiver creator UID.
 clear_events();receiver.uid=10001;peer_uid=110001;receiver.sk_family=AF_INET6;memset(skb.data,0,sizeof(skb.data));skb.protocol=htons(ETH_P_IPV6);skb.data[14]=0x60;skb.data[20]=17;skb.data[37]=1;skb.data[53]=1;skb.data[54]=0x12;skb.data[55]=0x34;skb.data[56]=0x56;skb.data[57]=0x78;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&last_tuple.family==AF_INET6&&last_tuple.address.v6.daddr.s6_addr[15]==1&&last_tuple.dport==htons(0x5678));
 // True bounded queue, actual overflow, no report-cache advance on overflow.
 clear_events();for(unsigned i=0;i<512;i++){receiver.uid=10001+i;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);}T(loopback_count==512&&loopback_sequence==512);receiver.uid=20001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==512&&loopback_sequence==512&&loopback_losses==1);
 transfer=(struct gta3xlwifi_loopback_transfer){1,512,(uintptr_t)events,1,0};T(event_io(&transfer)==0&&transfer.count==512&&transfer.lost_events==1&&loopback_count==0);for(unsigned i=0;i<512;i++)T(events[i].sequence==i+1&&events[i].result==1&&events[i].reserved==0);
 T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==1&&loopback_sequence==513&&loopback_events[loopback_head].lost_events==1);
 // All copy/alloc faults retain the queue. No consume until BOTH user copies succeed.
 transfer=(struct gta3xlwifi_loopback_transfer){1,1,(uintptr_t)events,513,0};from_fail=from_calls+1;T(event_io(&transfer)==-EFAULT&&loopback_count==1);from_fail=0;alloc_fail=1;T(event_io(&transfer)==-ENOMEM&&loopback_count==1);alloc_fail=0;
 to_fail=to_calls+1;T(event_io(&transfer)==-EFAULT&&loopback_count==1);to_fail=0;to_fail=to_calls+2;T(event_io(&transfer)==-EFAULT&&loopback_count==1);to_fail=0;transfer.first_sequence=1;T(event_io(&transfer)==-ESTALE&&loopback_count==1);transfer.first_sequence=513;
 task.uid=task.euid=10001;T(event_io(&transfer)==-EPERM&&loopback_count==1);task.uid=task.euid=0;struct pid foreign_pid={0};task.tgid=&foreign_pid;T(event_io(&transfer)==-EPERM&&loopback_count==1);task.tgid=&parent_pid;T(event_io(&transfer)==0&&loopback_count==0);
 // Producer can append during sleeping user copies; acknowledged consume removes only its snapshot.
 clear_events();receiver.uid=10001;peer_uid=110001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==1);
 consume_transfer=(struct gta3xlwifi_loopback_transfer){1,1,(uintptr_t)events,1,0};copy_hook=pause_copy;copy_started=copy_continue=false;pthread_t consumer;T(pthread_create(&consumer,NULL,consume_thread,NULL)==0);assert(pthread_mutex_lock(&copy_mu)==0);while(!copy_started)pthread_cond_wait(&copy_cv,&copy_mu);assert(pthread_mutex_unlock(&copy_mu)==0);
 receiver.uid=10002;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==2);assert(pthread_mutex_lock(&copy_mu)==0);copy_continue=true;pthread_cond_broadcast(&copy_cv);assert(pthread_mutex_unlock(&copy_mu)==0);T(pthread_join(consumer,NULL)==0&&consume_result==0&&events[0].sequence==1&&loopback_count==1&&loopback_events[loopback_head].sequence==2);copy_hook=NULL;
 // Exact bounded LRU: a rate-limited lookup refreshes recency; eviction permits genuine re-report.
 clear_events();for(unsigned i=0;i<100;i++){receiver.uid=10001+i;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);}receiver.uid=10001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==100);receiver.uid=20001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==101);receiver.uid=10002;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==102);receiver.uid=10001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==102);
 // An expired key still refreshes LRU on a full ring (A17 lookup precedes reserve).
 clear_events();for(unsigned i=0;i<510;i++){receiver.uid=30001+i;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);}receiver.uid=10001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);mock_boottime=60000000000ULL;receiver.uid=20001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==512);mock_boottime=61000000000ULL;receiver.uid=10001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_losses==1);
 transfer=(struct gta3xlwifi_loopback_transfer){1,512,(uintptr_t)events,1,0};T(event_io(&transfer)==0&&loopback_count==0);mock_boottime=63000000000ULL;for(unsigned i=0;i<99;i++){receiver.uid=40001+i;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);}receiver.uid=20001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&loopback_count==100);
 clear_events();
 T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0);before_lookup=peer_lookups;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&peer_lookups==before_lookup&&loopback_count==0);T(netpolicy_flush(&owner,NULL)==0);T(event_io(&transfer)==-ENOTCONN);T(netpolicy_release(NULL,&owner)==0);lna_free(lna_current);lna_current=NULL;vfree(uid_image);uid_image=NULL;T(allocs==frees&&!rcu_depth&&!tag_depth);
 printf("loopback_passed_cases=%u permission_comparisons=%u\n",cases-before_cases,permission_comparisons);return 0;
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'egress-regression/receive-prerequisite/include'),str(O/'test.c'),'-o',str(O/'test')];x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.search(r'loopback_passed_cases=(\d+) permission_comparisons=(\d+)\n$',x.stdout);assert match and int(match[2])==98304
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,egress,prior,header,source,peer,driver,S/'net/netfilter/xt_qtaguid.c',android,ah,O/'test.c'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_A17_permission_comparisons':int(match[2]),'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
