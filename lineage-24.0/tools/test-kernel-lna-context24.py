#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Expose receive-context attachment gap using actual parser/rawUID/LNA store C.

A supplied full receiving socket is modeled as modern cgroup skb context does.
This is a synthetic composition counterexample, not device packet execution or
proof of a complete legacy receive hook. Success means the gap is reproduced.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','store-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
prior=a.store_host/'report.json';report=json.loads(prior.read_text());assert report['passed'];existing=a.store_host/'test.c';assert hashlib.sha256(existing.read_bytes()).hexdigest()==report['inputs_sha256'][str(existing)]
code=existing.read_text().split('int main(void){',1)[0].replace('static u32 state=0x12345678;static u32 random32', 'static u32 state=0x12345678;\nstatic u32 random32')
# Eliminate unrelated test-only helpers to keep -Werror. Store/oracle code stays.
for name in ['tx','compare','random32','reference_image','check_decision']:
 body=m.extract(code,name);code=code.replace(body,'')
code=code.replace('parent_pid,child_pid','parent_pid').replace('owner={1},foreign={2}','owner={1}').replace('static u32 state=0x12345678;','').replace('static unsigned cases,comparisons;','static unsigned cases;')
# Remaining oracle is deliberately called by the experiment as well.
code+=r'''
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <net/gta3xlwifi_packet.h>
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3
struct net{const void*user_ns;};struct sock{u32 uid;bool full;struct net*net;};
struct net_device{unsigned ifindex;};struct dst_entry{struct net_device*dev;};
struct sk_buff{u8 data[128];int length,network;u16 protocol;struct sock*sk;struct dst_entry*dst;};
struct xt_action_param{unsigned hooknum;const struct net_device*in;};
static uid_t overflowuid=65534;
static struct sock*skb_to_full_sk(const struct sk_buff*s){return s->sk&&s->sk->full?s->sk:NULL;}
static bool sk_fullsock(const struct sock*s){return s->full;}
static struct net*sock_net(struct sock*s){return s->net;}
static u32 sock_net_uid(struct net*n,struct sock*s){assert(s->net==n);return s->uid;}
static u32 from_kuid_munged(const void*n,u32 uid){assert(n==&init_user_ns);return uid;}
static struct dst_entry*skb_dst(const struct sk_buff*s){return s->dst;}
static int skb_network_offset(const struct sk_buff*s){return s->network;}
static int skb_copy_bits(const struct sk_buff*s,int off,void*out,int n){if(off<0||off+n>s->length)return -EFAULT;memcpy(out,s->data+off,n);return 0;}
'''
parser=S/'net/netfilter/gta3xlwifi_packet.c';raw=S/'net/netfilter/xt_qtaguid.c';code+='\n'.join(m.extract(parser.read_text(),n) for n in ['gta3xlwifi_packet_read','gta3xlwifi_parse_packet'])+'\n'+'\n'.join(m.extract(raw.read_text(),n) for n in ['gta3xlwifi_raw_socket_uid','gta3xlwifi_lna_mt'])
code+=r'''
int main(void){
 struct gta3xlwifi_lna_entry deny={.prefix_bits=0,.allowed=0};
 struct gta3xlwifi_lna_transfer t={1,1,0,0,1,(uintptr_t)&deny,0};
 T(netpolicy_open(NULL,&owner)==0);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);
 onetwork=&deny;oncount=1;ohost=NULL;ohcount=0;
 struct net net={&init_user_ns};struct sock receiver={10001,true,&net};
 struct sk_buff skb={.length=128,.protocol=htons(ETH_P_IP)};skb.data[0]=0x45;skb.data[9]=17;
 struct net_device input={17};struct xt_action_param par={1,&input};
 struct in6_addr remote={0};T(oracle_blocked(receiver.uid,17,&remote,17,0));
 T(!gta3xlwifi_lna_mt(&skb,&par)); // Unassociated raw UID65534 normalizes to root.
 struct sock*saved=skb.sk;skb.sk=&receiver; // Explicit fixture of modern wrapper binding.
 T(gta3xlwifi_lna_mt(&skb,&par));skb.sk=saved;T(skb.sk==NULL);
 T(netpolicy_flush(&owner,NULL)==0);T(netpolicy_release(NULL,&owner)==0);lna_free(lna_current);lna_current=NULL;
 T(allocs==frees);printf("passed_cases=%u context_gap_reproduced=1\n",cases);
}
'''
for name in ['gta3xlwifi_local_network.h','gta3xlwifi_netpolicy.h','gta3xlwifi_uid_permissions.h']:
 src=a.store_host/'include/linux/netfilter'/name;dest=O/'include/linux/netfilter'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(src.read_bytes())
head=S/'include/net/gta3xlwifi_packet.h';dest=O/'include/net/gta3xlwifi_packet.h';dest.parent.mkdir(parents=True);dest.write_bytes(head.read_bytes());(O/'test.c').write_text(code)
cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')];x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=30,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
paths=[Path(__file__),helper,prior,existing,parser,raw,head,O/'test.c'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();(O/'report.json').write_text(json.dumps({'gap_reproduced':True,'scope':__doc__,'inputs_sha256':{str(p):sha(p) for p in paths},'plain_netfilter_input_attachment_approved':False,'full_receiving_socket_context_required':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; attachment gap, NOT enforcement approval')
