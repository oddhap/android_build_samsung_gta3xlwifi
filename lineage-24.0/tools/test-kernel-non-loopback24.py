#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare real private kernel owner-skip/non-loopback bodies with actual A17 parser/skip code.

The skb and relative byte-loading operations are fixtures, including errors and
nonlinear-access failure. A17 relative L3 parsing is the intended semantic
reference, not a claim that this 4.4 kernel executes modern BPF. No packets,
firewall hooks, metered/LNA decisions or network readiness are established.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
kernel=S/'net/netfilter/gta3xlwifi_owner_skip.c';uapi=S/'include/uapi/linux/netfilter/gta3xlwifi_owner_skip.h';ref=A/'packages/modules/Connectivity/bpf/progs/netd.c';header=ref.with_name('netd.h');helpers=ref.with_name('bpf_net_helpers.h');r=ref.read_text();h=helpers.read_text()
start=h.index('struct tcphdr_with_flags16 {');b=h.index('{',start);depth=1;i=b+1
while depth:
 depth+=(h[i]=='{')-(h[i]=='}');i+=1
struct=h[start:i+1];assert struct.endswith('};')
packet=header.read_text().split('// IP packet data from an __sk_buff\n',1)[1].split('STRUCT_SIZE(',1)[0]
macros='\n'.join(line for line in h.splitlines() if any(line.startswith('#define '+n+'(') for n in ['TCP_OFFSET','IP4_OFFSET','IP6_OFFSET']))
macros+='\n'+'\n'.join(line for line in r.splitlines() if any(line.startswith('#define '+n+' ') for n in ['IPPROTO_IHL_OFF','TCP_FLAG8_OFF','TCP_FLAG8_FIN','TCP_FLAG8_RST']))
export=O/'include/linux/netfilter/gta3xlwifi_owner_skip.h';export.parent.mkdir(parents=True);export.write_bytes(uapi.read_bytes())
code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/netfilter/gta3xlwifi_owner_skip.h>
typedef uint8_t u8;
#define function static
#define NF_INET_LOCAL_IN 1
#define NF_INET_FORWARD 2
#define NF_INET_LOCAL_OUT 3
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
static uint16_t htons(uint16_t x){return __builtin_bswap16(x);}
static uint32_t htonl(uint32_t x){return __builtin_bswap32(x);}
struct user_namespace{int unused;};static struct user_namespace init_user_ns,other_ns;static struct user_namespace* ns=&init_user_ns;
static struct user_namespace* current_user_ns(void){return ns;}
struct sk_buff{uint8_t data[1200];size_t length;int network;uint16_t protocol;};
struct net_device{unsigned ifindex;};
struct xt_action_param{const void* matchinfo;unsigned hooknum;const struct net_device* in;const struct net_device* out;};struct xt_mtchk_param{const void* matchinfo;unsigned family;};
static int failure=-1;
static int skb_network_offset(const struct sk_buff* skb){return skb->network;}
static int skb_copy_bits(const struct sk_buff* skb,int offset,void* out,int length){
 if(offset<0||offset==failure||(size_t)(offset+length)>skb->length){memset(out,0xa5,length);return -EFAULT;}
 memcpy(out,skb->data+offset,length);return 0;
}
'''+ '\n'.join(m.extract(kernel.read_text(),n) for n in ['gta3xlwifi_owner_read','gta3xlwifi_owner_skip_mt','gta3xlwifi_owner_skip_check','gta3xlwifi_non_loopback_mt'])+'\n'+struct+'\n'+packet+'\n'+macros+r'''
struct kver_uint{unsigned version;};struct egress_bool{bool egress;};
struct __sk_buff{const struct sk_buff* skb;uint16_t protocol;};
static long bpf_skb_load_bytes_net(const struct __sk_buff* skb,const int offset,void* out,const int length,const struct kver_uint kver){
 (void)kver;int result=skb_copy_bits(skb->skb,skb->skb->network+offset,out,length);if(result)memset(out,0,length);return result;
}
'''+m.extract(r,'parse_skb')+'\n'+m.extract(r,'skip_owner_match')+r'''
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
static void compare(struct sk_buff* skb){
 struct __sk_buff oracle={skb,skb->protocol};SkbIpPacketData parsed={0};
 (void)parse_skb(&parsed,&oracle,(struct kver_uint){515});
 for(unsigned hook=NF_INET_LOCAL_IN;hook<=NF_INET_LOCAL_OUT;hook+=2){
  struct xt_action_param p={.matchinfo=NULL,.hooknum=hook};struct egress_bool e={hook==NF_INET_LOCAL_OUT};
  bool expected=skip_owner_match(&parsed,e);bool actual=gta3xlwifi_owner_skip_mt(skb,&p);
  assert(actual==expected);++comparisons;
 }
}
int main(void){
 struct gta3xlwifi_owner_skip_match info={0};struct xt_mtchk_param c={&info,NFPROTO_IPV4};
 T(sizeof(info)==4);T(gta3xlwifi_owner_skip_check(&c)==0);c.family=NFPROTO_IPV6;T(gta3xlwifi_owner_skip_check(&c)==0);c.family=0;T(gta3xlwifi_owner_skip_check(&c)==-EINVAL);c.family=NFPROTO_IPV4;info.reserved=1;T(gta3xlwifi_owner_skip_check(&c)==-EINVAL);info.reserved=0;ns=&other_ns;T(gta3xlwifi_owner_skip_check(&c)==-EINVAL);ns=&init_user_ns;
 struct sk_buff skb={.length=1200};struct xt_action_param p={.matchinfo=&info,.hooknum=NF_INET_LOCAL_IN};T(!gta3xlwifi_owner_skip_mt(NULL,&p));p.hooknum=NF_INET_FORWARD;T(!gta3xlwifi_owner_skip_mt(&skb,&p));
 T(offsetof(struct tcphdr_with_flags16,flags16)+1==13);T(sizeof(struct ipv6hdr)==40);
 const uint8_t flags[]={0,1,2,4,5,16,255};
 for(int net=0;net<=14;net+=14){
  skb.network=net;skb.protocol=htons(ETH_P_IP);
  for(unsigned ihl=0;ihl<256;ihl++)for(unsigned proto=0;proto<256;proto++)for(unsigned f=0;f<sizeof(flags);f++){
   memset(skb.data,0,sizeof(skb.data));skb.data[net]=ihl;skb.data[net+9]=proto;
   unsigned offset=(ihl&15)*4;skb.data[net+offset+13]=flags[f];compare(&skb);
  }
  skb.protocol=htons(ETH_P_IPV6);
  for(unsigned first=0;first<256;first++)for(unsigned f=0;f<256;f++){
   memset(skb.data,0,sizeof(skb.data));skb.data[net+6]=first;skb.data[net+53]=f;compare(&skb);
  }
  for(unsigned ext=0;ext<2;ext++)for(unsigned proto=0;proto<256;proto++)for(unsigned len=0;len<256;len++)for(unsigned f=0;f<sizeof(flags);f++){
   memset(skb.data,0,sizeof(skb.data));skb.data[net+6]=ext?IPPROTO_DSTOPTS:IPPROTO_HOPOPTS;skb.data[net+40]=proto;skb.data[net+41]=len;
   uint8_t offset=(uint8_t)(40+(len+1)*8);skb.data[net+offset+13]=flags[f];compare(&skb);
  }
 }
 // Truncated headers/options and read failures must preserve zero-on-failure,
 // including failures after the IPv4 version or option next-protocol was read.
 for(unsigned variant=0;variant<6;variant++)for(unsigned length=0;length<310;length++){
  memset(skb.data,0,sizeof(skb.data));skb.network=14;skb.length=length;skb.protocol=htons(variant<2?ETH_P_IP:ETH_P_IPV6);
  skb.data[14]=0x45;skb.data[23]=variant?IPPROTO_TCP:IPPROTO_ESP;skb.data[20]=variant<4?IPPROTO_TCP:IPPROTO_HOPOPTS;
  skb.data[54]=IPPROTO_TCP;skb.data[55]=1;skb.data[47]=5;skb.data[67]=5;skb.data[83]=5;compare(&skb);
  skb.length=1200;failure=length;compare(&skb);failure=-1;
 }
 skb.protocol=0;compare(&skb);T(comparisons>5000000);
 struct net_device input={1},output={7};p.in=&input;p.out=&output;
 p.hooknum=NF_INET_LOCAL_IN;T(!gta3xlwifi_non_loopback_mt(&skb,&p));
 p.hooknum=NF_INET_LOCAL_OUT;T(gta3xlwifi_non_loopback_mt(&skb,&p));
 output.ifindex=1;input.ifindex=7;
 p.hooknum=NF_INET_LOCAL_IN;T(gta3xlwifi_non_loopback_mt(&skb,&p));
 p.hooknum=NF_INET_LOCAL_OUT;T(!gta3xlwifi_non_loopback_mt(&skb,&p));
 p.in=p.out=NULL;T(gta3xlwifi_non_loopback_mt(&skb,&p));
 p.hooknum=NF_INET_LOCAL_IN;T(gta3xlwifi_non_loopback_mt(&skb,&p));
 T(!gta3xlwifi_non_loopback_mt(NULL,&p));p.hooknum=NF_INET_FORWARD;
 T(!gta3xlwifi_non_loopback_mt(&skb,&p));
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-O2','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=120);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',x.stdout);assert match and int(match[1])>=10 and int(match[2])>5000000
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,kernel,uapi,ref,header,helpers,export,O/'test.c']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_android17_parse_skip_comparisons':int(match[2]),'stderr':x.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual A17 parse/skip and real kernel bodies, fatal UBSan fixtures')
