#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the actual tuple-to-creator helper against kernel lookup/ref contracts.

Real peer and creator-reader/full-socket/request-conversion C bodies. Lookup,
objects, namespaces and reference effects are fixtures; no actual socket search,
packet eligibility, permission policy, BPF map or readiness is executed.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-kernel','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();K=a.reference_kernel.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=S/'net/netfilter/gta3xlwifi_socket_peer.c';header=S/'include/net/gta3xlwifi_socket_peer.h';core=K/'net/core/sock.c';sock=K/'include/net/sock.h';inet=K/'include/net/inet_sock.h';request=K/'include/net/request_sock.h';states=K/'include/net/tcp_states.h'
# The old kernel's request holds the listener until request destruction. The
# new helper must retain the original request while reading its borrowed parent.
rt=request.read_text();assert 'sock_hold(sk_listener);\n\t\t\treq->rsk_listener = sk_listener;' in rt and 'if (req->rsk_listener)\n\t\tsock_put(req->rsk_listener);' in rt
export=O/'include/net/gta3xlwifi_socket_peer.h';export.parent.mkdir(parents=True);export.write_bytes(header.read_bytes());(O/'tcp_states.h').write_bytes(states.read_bytes())
reader=m.extract(core.read_text(),'gta3xlwifi_socket_creator_uid').replace('gta3xlwifi_socket_creator_uid','actual_creator_uid',1)
code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "tcp_states.h"
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define CONFIG_INET 1
#define CONFIG_IPV6 1
#define IS_ENABLED(x) (x)
#include <net/gta3xlwifi_socket_peer.h>
struct net{unsigned id;};static struct net fixture_net={123};
struct inet_hashinfo{int unused;};static struct inet_hashinfo tcp_hashinfo;
struct sock{unsigned sk_state,sk_family;u32 sk_gta_creator_uid;bool sk_gta_creator_valid;};
struct request_sock{struct sock* rsk_listener;};static struct request_sock request;
static struct sock original,listener;static struct sock* returned;
static unsigned references,lookups,put_count,get_count,expected_kind;
static int expected_ifindex;static struct gta3xlwifi_socket_peer_tuple expected_tuple;
static struct request_sock* inet_reqsk(struct sock* sk){assert(references==1&&sk==returned&&sk->sk_state==TCP_NEW_SYN_RECV);return &request;}
'''+m.extract(sock.read_text(),'sk_fullsock')+'\n'+m.extract(inet.read_text(),'sk_to_full_sk')+'\n'+reader+r'''
static bool gta3xlwifi_socket_creator_uid(const struct sock* sk,u32* uid){assert(references==1);++get_count;return actual_creator_uid(sk,uid);}
static void sock_gen_put(struct sock* sk){assert(references==1&&sk==returned);++put_count;references=0;original.sk_gta_creator_uid=0;listener.sk_gta_creator_uid=0;original.sk_gta_creator_valid=listener.sk_gta_creator_valid=false;}
static struct sock* record(unsigned kind,struct net* net,const void* saddr,const void* daddr,size_t size,uint16_t sport,uint16_t dport,int index){
 assert(net==&fixture_net&&index==expected_ifindex&&kind==expected_kind);assert(sport==expected_tuple.sport&&dport==expected_tuple.dport);
 const void* expected_source=expected_tuple.family==AF_INET?(void*)&expected_tuple.address.v4.saddr:(void*)&expected_tuple.address.v6.saddr;
 const void* expected_dest=expected_tuple.family==AF_INET?(void*)&expected_tuple.address.v4.daddr:(void*)&expected_tuple.address.v6.daddr;
 assert(memcmp(saddr,expected_source,size)==0&&memcmp(daddr,expected_dest,size)==0);++lookups;assert(references==0);references=returned?1:0;return returned;
}
static struct sock* inet_lookup(struct net* n,struct inet_hashinfo* h,uint32_t s,uint16_t sp,uint32_t d,uint16_t dp,int i){assert(h==&tcp_hashinfo);return record(0,n,&s,&d,4,sp,dp,i);}
static struct sock* udp4_lib_lookup(struct net* n,uint32_t s,uint16_t sp,uint32_t d,uint16_t dp,int i){return record(1,n,&s,&d,4,sp,dp,i);}
static struct sock* inet6_lookup(struct net* n,struct inet_hashinfo* h,const struct in6_addr* s,uint16_t sp,const struct in6_addr* d,uint16_t dp,int i){assert(h==&tcp_hashinfo);return record(2,n,s,d,16,sp,dp,i);}
static struct sock* udp6_lib_lookup(struct net* n,const struct in6_addr* s,uint16_t sp,const struct in6_addr* d,uint16_t dp,int i){return record(3,n,s,d,16,sp,dp,i);}
'''+m.extract(source.read_text(),'gta3xlwifi_socket_peer_uid')+r'''
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
int main(void){
 u32 out=0xaaaabbbb;struct gta3xlwifi_socket_peer_tuple tuple={.family=AF_INET,.protocol=IPPROTO_TCP,.sport=0x1234,.dport=0xabcd};
 T(!gta3xlwifi_socket_peer_uid(NULL,1,&tuple,&out)&&out==0xaaaabbbb);
 T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,NULL,&out)&&out==0xaaaabbbb);
 T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,&tuple,NULL));
 T(!gta3xlwifi_socket_peer_uid(&fixture_net,-1,&tuple,&out)&&out==0xaaaabbbb);
 tuple.family=1;T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,&tuple,&out)&&out==0xaaaabbbb);
 tuple.family=AF_INET;tuple.protocol=1;T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,&tuple,&out)&&out==0xaaaabbbb);
 tuple.family=AF_INET6;T(!gta3xlwifi_socket_peer_uid(&fixture_net,1,&tuple,&out)&&out==0xaaaabbbb);
 T(!lookups&&!put_count&&!get_count&&!references);
 const u32 uids[]={0,65534,110001,0xffffffff};
 for(unsigned family=0;family<2;family++)for(unsigned protocol=0;protocol<2;protocol++)for(unsigned kind=0;kind<7;kind++)for(unsigned u=0;u<4;u++)for(unsigned index=0;index<3;index++){
  memset(&tuple,0,sizeof(tuple));tuple.family=family?AF_INET6:AF_INET;tuple.protocol=protocol?IPPROTO_UDP:IPPROTO_TCP;tuple.sport=0x1234;tuple.dport=0xabcd;
  if(family){for(unsigned j=0;j<16;j++){tuple.address.v6.saddr.s6_addr[j]=j+1;tuple.address.v6.daddr.s6_addr[j]=31-j;}}
  else{tuple.address.v4.saddr=0x01020304;tuple.address.v4.daddr=0x11223344;}
  expected_tuple=tuple;expected_ifindex=index==2?7:(int)index;expected_kind=family*2+protocol;
  original=(struct sock){TCP_ESTABLISHED,AF_INET6,uids[u],true};listener=(struct sock){TCP_LISTEN,AF_INET6,uids[u],true};request.rsk_listener=&listener;returned=&original;
  // Returned socket family may be AF_INET6 for IPv4 dual-stack lookup. Never
  // force family equality to the packet when reading trusted kernel results.
  if(kind==1)original.sk_gta_creator_valid=false;
  if(kind==2)original.sk_state=TCP_TIME_WAIT;
  if(kind>=3&&kind<=5){original.sk_state=TCP_NEW_SYN_RECV;if(kind==4)listener.sk_gta_creator_valid=false;if(kind==5)request.rsk_listener=NULL;}
  if(kind==6)returned=NULL;
  references=lookups=put_count=get_count=0;out=0xaaaabbbb;
  bool expected=kind==0||kind==3;bool known=gta3xlwifi_socket_peer_uid(&fixture_net,expected_ifindex,&tuple,&out);
  assert(known==expected&&out==(expected?uids[u]:0xaaaabbbb));++comparisons;
  assert(lookups==1&&references==0&&put_count==(kind==6?0u:1u)&&get_count==(kind==6?0u:1u));++comparisons;
 }
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=30);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',x.stdout);assert match and int(match[1])==8 and int(match[2])==672
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,source,header,core,sock,inet,request,states,export,O/'tcp_states.h',O/'test.c']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'tuple_identity_reference_comparisons':int(match[2]),'stderr':x.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual peer/getter/convert bodies with lookup/ref fixtures, fatal UBSan')
