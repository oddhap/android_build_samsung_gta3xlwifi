#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual private packet parser/raw UID/LNA match against actual A17 packet parsing.

skb loading, routes, credentials, socket identity, LNA decision and registration
are fixtures. Checks full40-byte parsed value, real normalized UID/remote endpoint/
current device dispatch and honest registration features. No packet/hook runtime.
"""
import argparse,ast,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
old=Path(__file__).with_name('test-kernel-non-loopback-route24.py');tree=ast.parse(old.read_text());node=next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='code' for t in n.targets))
while isinstance(node,ast.BinOp):node=node.left
prefix=ast.literal_eval(node);prefix=prefix.replace('struct dst_entry* dst;','struct dst_entry* dst;struct sock* sk;')
# Reuse only stable skb/copy/route fixtures. Old owner functions are not inserted.
prefix=prefix.replace('#include <linux/netfilter/gta3xlwifi_owner_skip.h>','#include <linux/netfilter/gta3xlwifi_local_network.h>\n#include <net/gta3xlwifi_packet.h>')
prefix=prefix.replace('#include <net/gta3xlwifi_packet.h>','').replace('typedef uint8_t u8;','typedef uint8_t u8;\n#include <net/gta3xlwifi_packet.h>')
prefix+='''
typedef uint32_t u32;typedef uint16_t u16;typedef uint32_t uid_t;
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define NFPROTO_UNSPEC 0
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) do{(x)=(v);}while(0)
static uid_t overflowuid=65534;
struct net{struct user_namespace*user_ns;};struct sock{u32 uid;bool full;struct net*net;};
static struct sock* skb_to_full_sk(const struct sk_buff*s){return s->sk&&s->sk->full?s->sk:NULL;}
static bool sk_fullsock(const struct sock*s){return s->full;}
static struct net* sock_net(struct sock*s){return s->net;}
static u32 sock_net_uid(struct net*n,struct sock*s){assert(n==s->net);return s->uid;}
static u32 from_kuid_munged(struct user_namespace*n,u32 u){assert(n==&init_user_ns||n==&other_ns);return u;}
static u32 expected_uid,expected_index;static struct in6_addr expected_remote;static u16 expected_proto;static __be16 expected_port;static unsigned decisions;static bool decision;
static bool gta3xlwifi_lna_blocked(u32 uid,u32 index,const struct in6_addr*ip,u16 proto,__be16 port){assert(uid==expected_uid&&index==expected_index&&!memcmp(ip,&expected_remote,16)&&proto==expected_proto&&port==expected_port);++decisions;return decision;}
struct xt_match{const char*name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void*me;};
'''
parser=S/'net/netfilter/gta3xlwifi_packet.c';raw=S/'net/netfilter/xt_qtaguid.c';pr=parser.read_text();rt=raw.read_text();ref=A/'packages/modules/Connectivity/bpf/progs/netd.c';header=ref.with_name('netd.h');helpers=ref.with_name('bpf_net_helpers.h');r=ref.read_text();h=helpers.read_text()
start=h.index('struct tcphdr_with_flags16 {');b=h.index('{',start);depth=1;i=b+1
while depth:depth+=(h[i]=='{')-(h[i]=='}');i+=1
struct=h[start:i+1];packet=header.read_text().split('// IP packet data from an __sk_buff\n',1)[1].split('STRUCT_SIZE(',1)[0]
macros='\n'.join(line for line in h.splitlines() if any(line.startswith('#define '+n+'(') for n in ['TCP_OFFSET','IP4_OFFSET','IP6_OFFSET']))
macros+='\n'+'\n'.join(line for line in r.splitlines() if any(line.startswith('#define '+n+' ') for n in ['IPPROTO_IHL_OFF','TCP_FLAG8_OFF']))
actual='\n'.join(m.extract(pr,n) for n in ['gta3xlwifi_packet_read','gta3xlwifi_parse_packet'])+'\n'+m.extract(rt,'gta3xlwifi_raw_socket_uid')+'\nstatic bool gta3xlwifi_lna_registered;\n'+'\n'.join(m.extract(rt,n) for n in ['gta3xlwifi_lna_packet_features','gta3xlwifi_lna_mt','gta3xlwifi_lna_check'])
metadata=rt[rt.index('static struct xt_match gta3xlwifi_lna_reg'):rt.index('static int __init gta3xlwifi_lna_init')]
register='static int registration_error;static unsigned registrations;static int xt_register_match(struct xt_match*m){assert(m==&gta3xlwifi_lna_reg);++registrations;return registration_error;}\n'+m.extract(rt,'gta3xlwifi_lna_init')
oracle=struct+'\n'+packet+'\n'+macros+r'''
struct kver_uint{unsigned version;};struct __sk_buff{const struct sk_buff*skb;uint16_t protocol;};
static long bpf_skb_load_bytes_net(const struct __sk_buff*s,const int offset,void*out,const int len,const struct kver_uint k){(void)k;int result=skb_copy_bits(s->skb,s->skb->network+offset,out,len);if(result)memset(out,0,len);return result;}
'''+m.extract(r,'parse_skb')
tests=r'''
static unsigned cases,comparisons,dispatches;
#define T(x) do{assert(x);++cases;}while(0)
static struct net net={&init_user_ns};static struct sock socket={10001,true,&net};
static struct net_device input={17},stale={777},routed={7};static struct dst_entry route={&routed};
static void compare(struct sk_buff*skb){
 SkbIpPacketData expected={0};struct __sk_buff ob={skb,skb->protocol};bool parsed=parse_skb(&expected,&ob,(struct kver_uint){515});
 struct gta3xlwifi_packet actual;memset(&actual,0x5a,sizeof(actual));bool result=gta3xlwifi_parse_packet(skb,&actual);assert(parsed==result&&!memcmp(&actual,&expected,40));++comparisons;
 const u32 uids[]={0,1000,9999,10001,65534,100001,101000,0xffffffff};socket.uid=uids[comparisons%8];socket.full=comparisons%3!=0;skb->sk=comparisons%5?&socket:NULL;net.user_ns=comparisons%2?&init_user_ns:&other_ns;overflowuid=comparisons%11?65534:777;
 skb->dst=comparisons%7?&route:NULL;
 for(unsigned hook=1;hook<=3;hook+=2){
  struct xt_action_param p={.hooknum=hook,.in=comparisons%9?&input:NULL,.out=&stale};
  expected_uid=skb->sk&&socket.full?socket.uid:overflowuid;if(expected_uid==65534)expected_uid=0;
  expected_index=hook==3?(skb->dst?routed.ifindex:0):(p.in?input.ifindex:0);expected_remote=hook==3?expected.daddr:expected.saddr;expected_proto=expected.ip_proto;expected_port=hook==3?expected.dport:expected.sport;decisions=0;decision=comparisons&1;
  assert(gta3xlwifi_lna_mt(skb,&p)==(parsed&&decision)&&decisions==parsed);++dispatches;
 }
}
int main(void){
 T(sizeof(struct gta3xlwifi_packet)==40&&sizeof(SkbIpPacketData)==40);T(sizeof(struct gta3xlwifi_lna_match)==4);
 struct gta3xlwifi_lna_match info={0};struct xt_mtchk_param chk={&info,NFPROTO_IPV4};T(gta3xlwifi_lna_check(&chk)==0);chk.family=NFPROTO_IPV6;T(gta3xlwifi_lna_check(&chk)==0);chk.family=0;T(gta3xlwifi_lna_check(&chk)==-EINVAL);chk.family=NFPROTO_IPV4;info.reserved=1;T(gta3xlwifi_lna_check(&chk)==-EINVAL);info.reserved=0;ns=&other_ns;T(gta3xlwifi_lna_check(&chk)==-EINVAL);ns=&init_user_ns;
 T(gta3xlwifi_lna_packet_features()==0);registration_error=-ENOMEM;T(gta3xlwifi_lna_init()==-ENOMEM&&gta3xlwifi_lna_packet_features()==0);registration_error=0;T(gta3xlwifi_lna_init()==0&&gta3xlwifi_lna_packet_features()==16&&registrations==2);
 T(gta3xlwifi_lna_reg.match==gta3xlwifi_lna_mt&&gta3xlwifi_lna_reg.hooks==((1<<1)|(1<<3))&&gta3xlwifi_lna_reg.matchsize==4&&!strcmp(gta3xlwifi_lna_reg.name,"gta3xlwifi_lna"));
 struct sk_buff skb={.length=1200};struct xt_action_param p={.hooknum=1};T(!gta3xlwifi_lna_mt(NULL,&p));T(!gta3xlwifi_lna_mt(&skb,NULL));p.hooknum=2;T(!gta3xlwifi_lna_mt(&skb,&p));struct gta3xlwifi_packet actual;T(!gta3xlwifi_parse_packet(NULL,&actual));T(!gta3xlwifi_parse_packet(&skb,NULL));
 const u8 flags[]={0,1,2,4,5,16,255};
 for(int netoff=0;netoff<=14;netoff+=14){
  skb.network=netoff;skb.protocol=htons(ETH_P_IP);
  for(unsigned ihl=0;ihl<256;ihl++)for(unsigned proto=0;proto<256;proto++)for(unsigned f=0;f<sizeof(flags);f++){
   for(unsigned b=0;b<sizeof(skb.data);b++){skb.data[b]=(b*7+proto+f)&255;}skb.data[netoff]=ihl;skb.data[netoff+9]=proto;skb.data[netoff+(ihl&15)*4+13]=flags[f];compare(&skb);
  }
  skb.protocol=htons(ETH_P_IPV6);
  for(unsigned first=0;first<256;first++)for(unsigned f=0;f<256;f++){
   for(unsigned b=0;b<sizeof(skb.data);b++){skb.data[b]=(b*3+first+f)&255;}skb.data[netoff+6]=first;skb.data[netoff+53]=f;compare(&skb);
  }
  for(unsigned ext=0;ext<2;ext++)for(unsigned proto=0;proto<256;proto++)for(unsigned len=0;len<256;len++)for(unsigned f=0;f<sizeof(flags);f++){
   for(unsigned b=0;b<sizeof(skb.data);b++){skb.data[b]=(b*5+proto+f)&255;}skb.data[netoff+6]=ext?IPPROTO_DSTOPTS:IPPROTO_HOPOPTS;skb.data[netoff+40]=proto;skb.data[netoff+41]=len;u8 off=(u8)(40+(len+1)*8);skb.data[netoff+off+13]=flags[f];compare(&skb);
  }
 }
 for(unsigned variant=0;variant<6;variant++)for(unsigned length=0;length<310;length++){
  skb.network=14;skb.length=length;skb.protocol=htons(variant<2?ETH_P_IP:ETH_P_IPV6);for(unsigned b=0;b<sizeof(skb.data);b++)skb.data[b]=b*11;skb.data[14]=0x45;skb.data[23]=variant?IPPROTO_TCP:IPPROTO_ESP;skb.data[20]=variant<4?IPPROTO_TCP:IPPROTO_HOPOPTS;skb.data[54]=IPPROTO_ICMPV6;skb.data[55]=1;compare(&skb);skb.length=1200;failure=length;compare(&skb);failure=-1;
 }
 skb.protocol=0;compare(&skb);T(comparisons>2800000&&dispatches==2*comparisons);
 printf("passed_cases=%u parser_comparisons=%u endpoint_dispatches=%u\n",cases,comparisons,dispatches);
}
'''
if 'gta3xlwifi_socket_context_uid(' in actual:
 prefix+='\nstatic bool gta3xlwifi_socket_context_uid(const struct sk_buff*s,u32*u){(void)s;(void)u;return false;} /* outside private evaluator regression */\n'
code='\n'.join([prefix,actual,metadata,register,oracle,tests]);(O/'test.c').write_text(code)
paths=[Path(__file__),helper,old,parser,raw,ref,header,helpers]
for src,dst in [(S/'include/net/gta3xlwifi_packet.h',O/'include/net/gta3xlwifi_packet.h'),(S/'include/uapi/linux/netfilter/gta3xlwifi_local_network.h',O/'include/linux/netfilter/gta3xlwifi_local_network.h')]:dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes());paths +=[src,dst]
cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')];x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=120);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.fullmatch(r'passed_cases=(\d+) parser_comparisons=(\d+) endpoint_dispatches=(\d+)\n',x.stdout);assert match and int(match[2])>2800000 and int(match[3])==2*int(match[2]);paths.append(O/'test.c');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'parser_comparisons':int(match[2]),'endpoint_dispatches':int(match[3]),'command':cmd,'inputs_sha256':{str(p):sha(p) for p in paths},'kernel_runtime_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual parser/rawUID/match + A17 oracle, fatal UBSan fixtures')
