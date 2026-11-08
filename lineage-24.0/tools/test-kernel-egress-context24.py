#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual full-socket IPv4/IPv6/multicast egress LNA gate and ownership tests.

Reuses hash-bound real receive/store/parser test, then compiles actual egress
policy and wrappers. Socket, skb, downstream output and RCU are host fixtures;
no runtime networking/readiness or hardware claims.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-kernel','store-host','packet-host','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_kernel.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
receive=Path(__file__).with_name('test-kernel-receive-context24.py');cmd=['python3',str(receive)]
for n in ['source','base-kernel','store-host','packet-host','android-source']:cmd+=['--'+n,str(getattr(a,n.replace('-','_')))]
cmd+=['--output',str(O/'receive-prerequisite')];subprocess.run(cmd,check=True)
prior=O/'receive-prerequisite/test.c';code=prior.read_text().replace('int main(void){','static int receive_main(void){')
# Existing receive harness ended main with implicit return; make its reuse explicit.
code=code.rstrip();assert code.endswith('}');code=code[:-1]+'return 0;\n}\n'
raw=S/'net/netfilter/xt_qtaguid.c';text=raw.read_text();code+='\n'+m.extract(text,'gta3xlwifi_egress_features')+'\n'+m.extract(text,'gta3xlwifi_egress_policy')+'\n'
v4=S/'net/ipv4/ip_output.c';v6=S/'net/ipv6/ip6_output.c';old4=B/'net/ipv4/ip_output.c';old6=B/'net/ipv6/ip6_output.c'
# Exact old slow/GSO/XFRM/fragmentation bodies retained behind the new wrappers.
for new,old,n in [(v4,old4,'ip_finish_output'),(v6,old6,'ip6_finish_output')]:
 assert m.extract(new.read_text(),'__'+n).replace('static int __'+n+'(', 'static int '+n+'(',1)==m.extract(old.read_text(),n)
 assert '#include <net/gta3xlwifi_receive.h>' in new.read_text()
mc=m.extract(v4.read_text(),'ip_mc_output');oldmc=m.extract(old4.read_text(),'ip_mc_output');assert mc.replace('ip_mc_finish_output);','dev_loopback_xmit);')==oldmc and mc.count('ip_mc_finish_output);')==2
ip6=m.extract(v6.read_text(),'ip6_output');oldip6=m.extract(old6.read_text(),'ip6_output');addition='\t/* Match modern output context before netfilter and the policy callback. */\n\tskb->protocol = htons(ETH_P_IPV6);\n\tskb->dev = dev;\n\n';assert ip6.replace(addition,'')==oldip6
assert ip6.index('skb->dev = dev')<ip6.index('NF_HOOK_COND')
android=A/'packages/modules/Connectivity/bpf/progs/netd.c';aids=A/'system/core/libcutils/include/private/android_filesystem_config.h';assert re.search(r'#define AID_CLAT\s+1029\b',aids.read_text());assert 'if (egress.egress && statsUid == AID_CLAT) return PASS;' in android.read_text()
clat_source=android.read_text();begin=clat_source.index('    // sock_uid will be',clat_source.index('function int bpf_traffic_account('));end=clat_source.index('    SkbIpPacketData packet_data = {};',begin)
code+=r'''
#define PASS 1
#define AID_CLAT 1029
struct egress_bool{bool egress;};typedef struct{u32 uid,tag;}UidTagValue;
static struct sock*oracle_socket;
static u32 bpf_get_socket_uid(struct __sk_buff*s){(void)s;return oracle_socket->uid;}
static u64 bpf_get_socket_cookie(struct __sk_buff*s){(void)s;return 7;}
static UidTagValue* bpf_cookie_tag_map_lookup_elem(u64*cookie){static UidTagValue value;assert(*cookie==7);if(tagged_sk!=oracle_socket)return NULL;value.uid=get_uid_from_tag(tagged.tag);value.tag=get_atag_from_tag(tagged.tag)>>32;return &value;}
static int oracle_clat(struct __sk_buff*skb,const struct egress_bool egress){
'''+clat_source[begin:end]+'(void)tag; return 0;\n}\n'
code+=r'''
static unsigned consumed,output4,output6,outputmc;static int output_error;
static void kfree_skb(struct sk_buff*s){assert(s);++consumed;}
static int __ip_finish_output(struct net*n,struct sock*sk,struct sk_buff*s){assert(n==&net&&s);(void)sk;++output4;++consumed;return output_error;}
static int __ip6_finish_output(struct net*n,struct sock*sk,struct sk_buff*s){assert(n==&net&&s);(void)sk;++output6;++consumed;return output_error;}
static int dev_loopback_xmit(struct net*n,struct sock*sk,struct sk_buff*s){assert(n==&net&&s);(void)sk;++outputmc;++consumed;return output_error;}
'''
for f,n in [(v4,'ip_finish_output'),(v6,'ip6_finish_output'),(v4,'ip_mc_finish_output')]:code+='\n'+m.extract(f.read_text(),n)
code+=r'''
static void*egress_thread(void*x){receive_result=gta3xlwifi_egress_policy(&receiver,x);return NULL;}
int main(void){
 assert(receive_main()==0);unsigned before_cases=cases;
 T(gta3xlwifi_egress_features()==64);T(netpolicy_open(NULL,&owner)==0);
 struct gta3xlwifi_lna_entry deny={.allowed=0};struct gta3xlwifi_lna_transfer image={1,1,0,0,1,(uintptr_t)&deny,0};T(io(GTA3XLWIFI_LNA_SET_IMAGE,&image)==0);
 struct sk_buff skb={.length=1166,.data_at=34,.network=-20,.protocol=htons(ETH_P_IP),.sk=&foreign,.dev=&device};skb.data[14]=0x45;skb.data[23]=17;skb.data[30]=192;skb.data[33]=7;
 receiver.uid=10001;receiver.full=true;receiver.sk_family=AF_INET;receiver.creator_uid=0;receiver.sk_filter=NULL;
 tagged_sk=&receiver;tagged.tag=1029;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
 T(gta3xlwifi_egress_policy(&receiver,&skb)==0);T(gta3xlwifi_receive_policy(&receiver,&skb)==-EPERM);tagged_sk=NULL;
 T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&skb.sk==&foreign&&skb.data_at==34&&skb.network==-20);skb.sk=NULL;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM&&skb.sk==NULL);
 receiver.uid=1029;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);tagged_sk=&receiver;tagged.tag=10001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);tagged_sk=NULL;receiver.uid=1051;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);receiver.uid=0;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);receiver.uid=65534;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);receiver.uid=10001;
 tagged_sk=&receiver;tagged.tag=((u64)0xffffff82<<32)|1051;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);tagged.tag=((u64)0xffffff81<<32)|1051;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);tagged.tag=((u64)0xffffff82<<32)|10001;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);
 module_passive=true;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EOPNOTSUPP);module_passive=false;tagged_sk=NULL;
 T(gta3xlwifi_egress_policy(NULL,&skb)==0);T(gta3xlwifi_egress_policy(&receiver,NULL)==0);receiver.full=false;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);receiver.full=true;receiver.sk_family=AF_UNIX;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);receiver.sk_family=AF_INET6;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);receiver.sk_family=AF_INET;
 // Actual IPv6 L3 packet, with supplied AF_INET6 socket and absent skb owner.
 u8 saved[1200];memcpy(saved,skb.data,sizeof(saved));memset(skb.data,0,sizeof(skb.data));skb.protocol=htons(ETH_P_IPV6);skb.data[14]=0x60;skb.data[20]=17;skb.data[38]=0xfd;receiver.sk_family=AF_INET6;
 T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);tagged_sk=&receiver;tagged.tag=1029;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);tagged_sk=NULL;
 memcpy(skb.data,saved,sizeof(saved));skb.protocol=htons(ETH_P_IP);receiver.sk_family=AF_INET;
 // Actual A17 traffic-account prefix, including absent-tag statsUid fallback.
 oracle_socket=&receiver;struct __sk_buff context={&skb,skb.protocol};
 const u32 uids[]={0,1000,1029,1051,10001,65534};
 for(unsigned family=0;family<2;family++)for(unsigned u=0;u<6;u++)for(unsigned meta=0;meta<4;meta++){
  receiver.sk_family=family?AF_INET6:AF_INET;receiver.uid=uids[u];tagged_sk=meta?&receiver:NULL;
  tagged.tag=meta==1?1029:meta==2?((u64)0xffffff82<<32)|1051:((u64)0xffffff81<<32)|10001;
  bool clat=oracle_clat(&context,(struct egress_bool){true});
  bool expected=clat||meta==2||uids[u]==0||uids[u]==1000||uids[u]==65534;
  T(gta3xlwifi_egress_policy(&receiver,&skb)==(expected?0:-EPERM));
 }
 receiver.uid=10001;receiver.sk_family=AF_INET;tagged_sk=NULL;
 // Prefix isolation proves destination address, port and real device are used.
 T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0);
 struct gta3xlwifi_packet packet;T(gta3xlwifi_parse_packet(&skb,&packet));
 deny.prefix_bits=192;memcpy(deny.key,&device.ifindex,4);memcpy(deny.key+4,&packet.daddr,16);memcpy(deny.key+20,&packet.ip_proto,2);memcpy(deny.key+22,&packet.dport,2);image.revision=2;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&image)==0);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
 T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);T(gta3xlwifi_receive_policy(&receiver,&skb)==0);device.ifindex=18;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);device.ifindex=17;skb.data[37]=1;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);skb.data[37]=0;T(gta3xlwifi_egress_policy(&receiver,&skb)==-EPERM);skb.dev=NULL;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);skb.dev=&device;
 // Ownership: each rejecting wrapper consumes once and never calls downstream.
 int (*wrappers[])(struct net*,struct sock*,struct sk_buff*)={ip_finish_output,ip6_finish_output,ip_mc_finish_output};
 for(unsigned i=0;i<3;i++){
  unsigned old=consumed,total=output4+output6+outputmc;T(wrappers[i](&net,&receiver,&skb)==-EPERM&&consumed==old+1&&output4+output6+outputmc==total);
  tagged_sk=&receiver;tagged.tag=1029;old=consumed;T(wrappers[i](&net,&receiver,&skb)==0&&consumed==old+1&&output4+output6+outputmc==total+1);
  output_error=-ENOBUFS;old=consumed;T(wrappers[i](&net,&receiver,&skb)==-ENOBUFS&&consumed==old+1&&output4+output6+outputmc==total+2);output_error=0;tagged_sk=NULL;
 }
 // Unknown protocol/read failure follows A17 LNA parser behavior, no owner changes.
 u16 protocol=skb.protocol;skb.protocol=0;T(gta3xlwifi_egress_policy(&receiver,&skb)==0);skb.protocol=protocol;
 // HOLD drains an output reader before it can finish, exactly as receive.
 pause_tag=true;tag_entered=continue_tag=drain_entered=hold_done=false;pthread_t reader,hold;
 T(pthread_create(&reader,NULL,egress_thread,&skb)==0);assert(pthread_mutex_lock(&rmu)==0);while(!tag_entered)pthread_cond_wait(&rcv,&rmu);assert(pthread_mutex_unlock(&rmu)==0);
 T(pthread_create(&hold,NULL,hold_thread,NULL)==0);assert(pthread_mutex_lock(&rmu)==0);while(!drain_entered)pthread_cond_wait(&rcv,&rmu);T(!hold_done&&active_readers>0);continue_tag=true;pthread_cond_broadcast(&rcv);assert(pthread_mutex_unlock(&rmu)==0);
 T(pthread_join(reader,NULL)==0&&pthread_join(hold,NULL)==0&&hold_result==0&&receive_result==-EPERM&&gta3xlwifi_netpolicy_held()&&active_readers==0);
 pause_tag=false;T(netpolicy_flush(&owner,NULL)==0);T(netpolicy_release(NULL,&owner)==0);lna_free(lna_current);lna_current=NULL;T(allocs==frees&&!rcu_depth&&!tag_depth);
 printf("egress_passed_cases=%u\n",cases-before_cases);return 0;
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'receive-prerequisite/include'),str(O/'test.c'),'-o',str(O/'test')];x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.search(r'egress_passed_cases=(\d+)\n$',x.stdout);assert match and int(match[1])>=50
paths=[Path(__file__),helper,receive,prior,raw,v4,v6,old4,old6,android,aids,S/'include/net/gta3xlwifi_receive.h',S/'include/uapi/linux/netfilter/gta3xlwifi_local_network.h',O/'test.c'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_android17_clat_fallback_cases':48,'output_original_body_identity':True,'multicast_callbacks_checked':2,'consume_once_error_and_success_checked':True,'HOLD_waits_for_output_reader':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
