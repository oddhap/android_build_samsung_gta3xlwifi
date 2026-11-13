#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual UID/app store plus actual receive/output functions and pinned A17 traffic-account oracle.

Credentials, socket metadata, parser and policy decisions are fixtures. Actual
packet hooks consume the same UID/tag sample and update the real bounded store.
This does not install rules or provide global readiness/hardware validation.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','reference-host','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();R=a.reference_host.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
h=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');sp=importlib.util.spec_from_file_location('extract',h);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
report=json.loads((R/'report.json').read_text());assert report['passed'] and report['actual_A17_GSO_comparisons']==9830400
fixture=R/'test.c';assert sha(fixture)==report['inputs_sha256'][str(fixture)]
module=B/'net/netfilter/gta3xlwifi_packet_stats.c';assert sha(module)==report['inputs_sha256'][str(module)]
shutil.copytree(R/'include',O/'include')
raw=S/'net/netfilter/xt_qtaguid.c';old=B/'net/netfilter/xt_qtaguid.c';rt=raw.read_text();bt=old.read_text()
for name in ['gta3xlwifi_socket_accounting','gta3xlwifi_receive_features','gta3xlwifi_egress_features','gta3xlwifi_iface_mt','gta3xlwifi_iface_check']:
 assert m.extract(rt,name)==m.extract(bt,name),name
# All source outside the two packet bodies plus one new helper/include is identical.
stripped=rt.replace(m.extract(rt,'gta3xlwifi_account_packet'),'')
start=stripped.index('/* UID/app accounting uses the SAME socket/tag sample');end=stripped.index('u32 gta3xlwifi_receive_features',start);stripped=stripped[:start]+stripped[end:]
for name in ['gta3xlwifi_receive_policy','gta3xlwifi_egress_policy']:stripped=stripped.replace(m.extract(stripped,name),m.extract(bt,name))
assert stripped==bt,'Unexpected code outside the intended packet delta'
code=fixture.read_text()
code=code.replace('struct sock{bool full;u32 sk_protocol;};','struct net{const void*user_ns;};struct sock{bool full;u32 sk_protocol;u32 uid;unsigned sk_family;struct net*net;};')
code=code.replace('struct sk_buff{u32 len;uint16_t protocol;struct shared_info shared;};','struct net_device{u32 ifindex;};struct sk_buff{u32 len;uint16_t protocol;struct shared_info shared;struct net_device*dev;};')
code=code.replace('struct __sk_buff{u32 len;uint16_t protocol;u32 gso_segs;struct bpf_sock*sk;};','struct __sk_buff{u32 len;uint16_t protocol;u32 gso_segs;struct bpf_sock*sk;u32 ifindex;};')
code=code.replace('struct sk_buff packet={64,0,{1}}','struct sk_buff packet={.len=64,.shared={1}}')
code=code.replace('struct sock sk={kind!=1,kind==2?IPPROTO_TCP:kind==3?IPPROTO_UDP:IPPROTO_GRE}','struct sock sk={.full=kind!=1,.sk_protocol=kind==2?IPPROTO_TCP:kind==3?IPPROTO_UDP:IPPROTO_GRE}')
code=code.replace('struct sk_buff frame={len,htons(family==0?ETH_P_IP:family==1?ETH_P_IPV6:0),{segments[seg]}}','struct sk_buff frame={.len=len,.protocol=htons(family==0?ETH_P_IP:family==1?ETH_P_IPV6:0),.shared={segments[seg]}}')
code=code.replace('struct __sk_buff oracle={len,frame.protocol,segments[seg],kind?&osk:NULL}','struct __sk_buff oracle={.len=len,.protocol=frame.protocol,.gso_segs=segments[seg],.sk=kind?&osk:NULL}')
for name in ['gta3xlwifi_receive_features','gta3xlwifi_egress_features']:
 code=code.replace(m.extract(code,name),'u32 '+name+'(void);')
code=code.replace('int main(void){','static int storage_regression_main(void){',1)
needle='printf("passed_cases=%u comparisons=%u concurrent_updates=80000\\n",cases,comparisons);'
assert needle in code;code=code.replace(needle,needle+'return 0;',1)
code+=r'''
static unsigned rcu_depth,uid_reads,tag_reads;
static void rcu_read_lock(void){++rcu_depth;}
static void rcu_read_unlock(void){assert(rcu_depth);--rcu_depth;}
static bool gta3xlwifi_netpolicy_held(void){assert(rcu_depth);return netpolicy_held;}
static const unsigned init_ns;
static struct net network={&init_ns};
static struct net*sock_net(struct sock*s){assert(rcu_depth);return s->net;}
static u32 sock_net_uid(struct net*n,struct sock*s){assert(n==s->net&&rcu_depth);++uid_reads;return s->uid;}
static u32 from_kuid_munged(const void*n,u32 uid){assert(n==&init_ns);return uid;}
typedef u64 tag_t;
struct sock_tag{tag_t tag;};static struct sock_tag tagged;static bool tag_present,module_passive;
static pthread_mutex_t sock_tag_list_lock=PTHREAD_MUTEX_INITIALIZER;
static struct sock_tag*get_sock_stat_nl(const struct sock*s){assert(s&&rcu_depth);++tag_reads;return tag_present?&tagged:NULL;}
static u32 get_uid_from_tag(tag_t t){return (u32)t;}
static u64 get_atag_from_tag(tag_t t){return t&0xffffffff00000000ULL;}
struct gta3xlwifi_packet{struct in6_addr saddr,daddr;u32 ip_proto;uint16_t sport,dport;};
static bool parsed,block_lna,block_loop;static int owner_match;
static bool gta3xlwifi_parse_packet(struct sk_buff*s,struct gta3xlwifi_packet*p){assert(s&&rcu_depth);memset(p,0,sizeof(*p));p->ip_proto=IPPROTO_UDP;return parsed;}
static int gta3xlwifi_socket_table_policy_meta(struct sock*s,struct sk_buff*b,bool out,u32 uid,bool dns){assert(s&&b&&uid==(s->uid==65534?0:s->uid)&&rcu_depth);return owner_match==0||(owner_match==2&&!dns)?-EPERM:0;}
static bool gta3xlwifi_lna_blocked(u32 uid,u32 ifindex,const struct in6_addr*addr,u32 proto,uint16_t port){assert(addr&&rcu_depth);return block_lna;}
static bool gta3xlwifi_loopback_blocked(struct net*n,u32 index,u32 uid,const struct gta3xlwifi_packet*p){assert(n==&network&&p&&rcu_depth);return index==1&&block_loop;}
'''
code+='\n'.join(m.extract(rt,n) for n in ['gta3xlwifi_socket_accounting','gta3xlwifi_account_packet','gta3xlwifi_receive_features','gta3xlwifi_egress_features','gta3xlwifi_receive_policy','gta3xlwifi_egress_policy'])+'\n'
android=A/'packages/modules/Connectivity/bpf/progs/netd.c';at=android.read_text()
code+=r'''
#define PASS 1
#define DROP 0
#define DROP_UNLESS_DNS 2
#define AID_CLAT 1029
#define AID_DNS 1051
#define SELECT_MAP_A 0
#define CURRENT_STATS_MAP_CONFIGURATION_KEY 1
#define DROP_REASON_LNP 1
#define EGRESS ((struct egress_bool){true})
#define INGRESS ((struct egress_bool){false})
#define ACCOUNT ((struct undo_bool){false})
#define UNDO ((struct undo_bool){true})
#define KVER_4_9 ((struct kver_uint){(4<<16)|(9<<8)})
#define API_IS_AT_LEAST(x,a) ((x).level>=1)
struct sdk_level_uint{unsigned level;};
typedef struct{u32 uid,tag,counterSet,ifaceIndex;}StatsKey;
typedef struct{u32 uid,tag;}UidTagValue;
typedef struct gta3xlwifi_packet SkbIpPacketData;
typedef struct{unsigned dropReasons;}SkStorageValue;
static UidTagValue otag;static u32 ouid,selected;static uint8_t os;
static StatsKey oracle_key;static StatsValue oracle_bank;static unsigned bank_updates,iface_undos;
static u32 bpf_get_socket_uid(struct __sk_buff*s){(void)s;return ouid;}
static u64 bpf_get_socket_cookie(struct __sk_buff*s){return s->sk?1:0;}
static UidTagValue*bpf_cookie_tag_map_lookup_elem(u64*c){(void)c;return tag_present?&otag:NULL;}
static bool parse_skb(SkbIpPacketData*p,struct __sk_buff*s,struct kver_uint k){(void)p;(void)s;(void)k;return parsed;}
static int bpf_owner_match(SkbIpPacketData*p,struct __sk_buff*s,u32 uid,struct egress_bool e,struct kver_uint k,struct sdk_level_uint l){return owner_match;}
static bool should_block_loopback_access_cached(SkbIpPacketData*p,struct __sk_buff*s,u32 uid){return block_loop;}
static bool should_block_local_network_packets(SkbIpPacketData*p,struct __sk_buff*s,u32 uid,u32 index,struct egress_bool e,struct kver_uint k){return block_lna;}
static SkStorageValue*bpf_sk_storage_get(struct bpf_sock*s,int a,int b){assert(false);return NULL;}
static void update_iface_stats_map(struct __sk_buff*s,u32*key,struct egress_bool e,struct kver_uint k,struct undo_bool u){assert(e.egress&&u.undo);++iface_undos;}
static uint8_t*bpf_uid_counterset_map_lookup_elem(u32*uid){(void)uid;return os?&os:NULL;}
static u32*bpf_configuration_map_lookup_elem(u32*key){assert(*key==1);return &selected;}
static void do_packet_tracing(struct __sk_buff*s,SkbIpPacketData*p,struct egress_bool e,u32 uid,u32 tag,struct kver_uint k){}
static void update_stats_map_A(const struct __sk_buff*s,const StatsKey*key,struct egress_bool e,struct kver_uint k,struct undo_bool u){assert(!u.undo);oracle_key=*key;++bank_updates;u32 zero=0;oracle_value=(StatsValue){0};update_app_uid_stats_map(s,&zero,e,k,u);oracle_bank=oracle_value;oracle_value=(StatsValue){0};}
static void update_stats_map_B(const struct __sk_buff*s,const StatsKey*key,struct egress_bool e,struct kver_uint k,struct undo_bool u){assert(false);}
'''
# Existing arithmetic oracle asserted its key was zero; traffic oracle uses realUID.
code=code.replace('assert(!*key);return &oracle_value;','(void)key;return &oracle_value;')
account=m.extract(at,'bpf_traffic_account');mask='asm("%0 &= 1" : "+r"(match));';assert account.count(mask)==1
# BPF-only verifier assembly is lowered to its exact C integer mask on the host.
code+='\n'+m.extract(at,'update_stats_with_config')+'\n'+account.replace(mask,'match &= 1;')+'\n'
code+=r'''
static unsigned hook_comparisons;
static void compare_flow(u32 raw_uid,unsigned tagcase,bool output,unsigned index,bool gso){
 reset_store();netpolicy_held=false;module_passive=false;uid_reads=tag_reads=0;ouid=raw_uid;selected=0;os=gso?1:0;
 u32 normalized=raw_uid==65534?0:raw_uid;
 tag_present=tagcase!=0;otag=(UidTagValue){tagcase==1?1051:tagcase==2?1051:tagcase==3?1029:20002,tagcase==1?0xffffff82:tagcase==2?7:tagcase==3?0:0x1234};tagged.tag=((u64)otag.tag<<32)|otag.uid;
 u32 charged=tag_present?otag.uid:normalized;if(charged==1051&&otag.tag==0xffffff82)charged=normalized;
 assert(!edit(GTA3XLWIFI_STATS_SET_COUNTERSET,charged,os));
 struct sock socket={.full=true,.sk_protocol=gso?IPPROTO_UDP:IPPROTO_TCP,.uid=raw_uid,.sk_family=AF_INET,.net=&network};
 struct net_device dev={index};struct sk_buff skb={.len=gso?65535:64,.protocol=htons(gso?ETH_P_IPV6:ETH_P_IP),.shared={gso?64:1},.dev=&dev};
 struct bpf_sock bs={socket.sk_protocol,true};struct __sk_buff ob={.len=skb.len,.protocol=skb.protocol,.gso_segs=skb.shared.gso_segs,.sk=&bs,.ifindex=index};
 oracle_key=(StatsKey){0};oracle_bank=(StatsValue){0};oracle_value=(StatsValue){0};bank_updates=iface_undos=0;
 int expected=bpf_traffic_account(&ob,(struct egress_bool){output},(struct kver_uint){(5<<16)|(4<<8)},(struct sdk_level_uint){1});
 StatsValue expected_app=oracle_value;int actual=output?gta3xlwifi_egress_policy(&socket,&skb):gta3xlwifi_receive_policy(&socket,&skb);
 assert(actual==(expected?0:-EPERM)&&uid_reads==1&&tag_reads==1&&!rcu_depth);
 assert(stats_banks[0].count==bank_updates&&app_count==bank_updates&&!stats_total_lost&&!app_lost);
 if(bank_updates){struct gta3xlwifi_packet_stats_entry*e=&stats_banks[0].rows[0].entry;struct gta3xlwifi_app_stats_entry*v=&app_rows[0].entry;
  assert(e->key.uid==oracle_key.uid&&e->key.tag==oracle_key.tag&&e->key.counterset==oracle_key.counterSet&&e->key.ifindex==oracle_key.ifaceIndex);
  assert(e->rx_packets==oracle_bank.rxPackets&&e->rx_bytes==oracle_bank.rxBytes&&e->tx_packets==oracle_bank.txPackets&&e->tx_bytes==oracle_bank.txBytes);
  assert(v->uid==oracle_key.uid&&v->rx_packets==expected_app.rxPackets&&v->rx_bytes==expected_app.rxBytes&&v->tx_packets==expected_app.txPackets&&v->tx_bytes==expected_app.txBytes);
 }
 ++hook_comparisons;
}
int main(void){
 assert(!storage_regression_main());
 const u32 uids[]={0,10001,65534,1029,1051};
 for(unsigned u=0;u<5;u++)for(unsigned t=0;t<5;t++)for(unsigned out=0;out<2;out++)for(unsigned idx=0;idx<3;idx++)for(unsigned gso=0;gso<2;gso++)for(unsigned parse=0;parse<2;parse++)for(int owner=0;owner<3;owner++)for(unsigned lna=0;lna<2;lna++)for(unsigned loop=0;loop<2;loop++){
  parsed=parse;owner_match=owner;block_lna=lna;block_loop=loop;compare_flow(uids[u],t,out,idx==0?0:idx==1?1:17,gso);
 }
 reset_store();struct sock s={.full=true,.sk_protocol=IPPROTO_TCP,.uid=10001,.sk_family=AF_INET6,.net=&network};struct net_device d={17};struct sk_buff b={.len=64,.protocol=htons(ETH_P_IPV6),.shared={1},.dev=&d};tag_present=false;module_passive=false;uid_reads=tag_reads=0;netpolicy_held=true;
 T(gta3xlwifi_receive_policy(&s,&b)==-EPERM&&stats_banks[0].count==1&&app_rows[0].entry.rx_packets==1&&uid_reads==1&&tag_reads==1);
 T(gta3xlwifi_egress_policy(&s,&b)==-EPERM&&app_rows[0].entry.tx_packets==0&&uid_reads==1&&tag_reads==1);
 module_passive=true;T(gta3xlwifi_receive_policy(&s,&b)==-EPERM&&stats_total_lost==1&&app_lost==1);netpolicy_held=false;T(gta3xlwifi_receive_policy(&s,&b)==-EOPNOTSUPP&&stats_total_lost==2);T(gta3xlwifi_egress_policy(&s,&b)==-EOPNOTSUPP&&stats_total_lost==2);module_passive=false;
 u32 count=stats_banks[0].count;s.full=false;T(gta3xlwifi_receive_policy(&s,&b)==0&&gta3xlwifi_egress_policy(&s,&b)==0&&stats_banks[0].count==count);s.full=true;s.sk_family=AF_UNIX;T(gta3xlwifi_receive_policy(&s,&b)==0&&gta3xlwifi_egress_policy(&s,&b)==0&&stats_banks[0].count==count);s.sk_family=AF_INET6;T(gta3xlwifi_receive_policy(NULL,&b)==0&&gta3xlwifi_egress_policy(&s,NULL)==0&&stats_banks[0].count==count);
 reset_store();netpolicy_held=false;parsed=false;owner_match=1;tag_present=false;b.dev=NULL;T(gta3xlwifi_receive_policy(&s,&b)==0&&stats_banks[0].rows[0].entry.key.ifindex==0);T(gta3xlwifi_egress_policy(&s,&b)==0&&app_rows[0].entry.tx_packets==1);
 reset_store();netpolicy_held=false;for(u32 n=0;n<5000;n++)assert(!gta3xlwifi_packet_stats_record(&s,&b,20000,n,0,false));tag_present=false;T(gta3xlwifi_receive_policy(&s,&b)==0&&stats_total_lost==1&&app_count==2);T(gta3xlwifi_egress_policy(&s,&b)==0&&stats_total_lost==2&&app_rows[1].entry.tx_packets==1);
 printf("hook_cases=%u actual_A17_flow_comparisons=%u\n",cases,hook_comparisons);return 0;
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=180,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);match=re.search(r'hook_cases=(\d+) actual_A17_flow_comparisons=(\d+)\n$',x.stdout);assert match and int(match[2])==7200
paths=[Path(__file__),h,fixture,R/'report.json',module,raw,old,android,O/'test.c',*[p for p in (O/'include/linux/netfilter').glob('*.h')]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_A17_flow_comparisons':int(match[2]),'source_outside_packet_delta_identical':True,'BPF_verifier_assembly_lowered_to_exact_C_mask':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'network_ready':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
