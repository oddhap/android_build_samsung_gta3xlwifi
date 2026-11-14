#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual leased runtime image/dispatch and LNA/loopback mode predicates vs pinned A17.

Credentials, RCU, peer lookup, permissions and event sinks are explicit fixtures.
The real immutable image, revision/lease confirmation and packet decisions run.
No real Binder, installed rules, device execution or global readiness claim.
"""
import argparse,ast,hashlib,importlib.util,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
h=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');sp=importlib.util.spec_from_file_location('extract',h);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
legacy=Path(__file__).with_name('test-kernel-uid-permissions24.py');tree=ast.parse(legacy.read_text());prefix=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='prefix' for t in n.targets))
inc=O/'include/linux/netfilter';inc.mkdir(parents=True)
for f in (B/'include/uapi/linux/netfilter').glob('gta3xlwifi*.h'):shutil.copyfile(f,inc/f.name)
header=S/'include/uapi/linux/netfilter/gta3xlwifi_runtime_policy.h';shutil.copyfile(header,inc/header.name)
prefix+='\n#include <arpa/inet.h>\n#include <linux/netfilter/gta3xlwifi_runtime_policy.h>\n#include <linux/netfilter/gta3xlwifi_local_network.h>\n#include <linux/netfilter/gta3xlwifi_loopback.h>\n#include <linux/netfilter/gta3xlwifi_iface_stats.h>\n#include <linux/netfilter/gta3xlwifi_packet_stats.h>\n'
module=S/'net/netfilter/gta3xlwifi_runtime_policy.c';driver=S/'net/netfilter/gta3xlwifi_netpolicy.c';loop=S/'net/netfilter/gta3xlwifi_loopback.c';local=S/'net/netfilter/gta3xlwifi_local_network.c';d=driver.read_text();ld=loop.read_text();oldDriver=(B/'net/netfilter/gta3xlwifi_netpolicy.c').read_text()
assert m.extract(d,'netpolicy_privileged')==m.extract(oldDriver,'netpolicy_privileged')
for name in ['netpolicy_open','netpolicy_drop_lease']:
 assert m.extract(d,name).replace('\t\tgta3xlwifi_runtime_invalidate();\n','')==m.extract(oldDriver,name)
for name in ['netpolicy_flush','netpolicy_release']:assert m.extract(d,name)==m.extract(oldDriver,name)
assert m.extract(ld,'loopback_permissions')==m.extract((B/'net/netfilter/gta3xlwifi_loopback.c').read_text(),'loopback_permissions')
assert m.extract(ld,'loopback_emit')==m.extract((B/'net/netfilter/gta3xlwifi_loopback.c').read_text(),'loopback_emit')
old_loop=(B/'net/netfilter/gta3xlwifi_loopback.c').read_text()
assert ld.replace('#include <net/gta3xlwifi_runtime_policy.h>\n','',1).replace(m.extract(ld,'gta3xlwifi_loopback_blocked'),m.extract(old_loop,'gta3xlwifi_loopback_blocked'),1)==old_loop
old_local=(B/'net/netfilter/gta3xlwifi_local_network.c').read_text();actual_local=local.read_text()
assert actual_local.replace('#include <net/gta3xlwifi_runtime_policy.h>\n','',1).replace('/* Actual selected A17 propagation/legacy-blocked-UID predicate. */','/* Exact migrated A17 exemption: literal0/1000, NOT appId/core range. */',1).replace('if (!gta3xlwifi_runtime_lna_needs_check(uid))','if (uid == 0 || uid == 1000 || (gta3xlwifi_uid_permissions(uid) & 1U))',1)==old_local
for rel in ['net/netfilter/gta3xlwifi_packet_stats.c','net/netfilter/xt_qtaguid.c','net/netfilter/gta3xlwifi_uid_permissions.c']:
 if (S/rel).exists():assert sha(S/rel)==sha(B/rel),rel

code=prefix+d[d.index('static DEFINE_MUTEX('):d.index('static bool netpolicy_privileged(')]+r'''
static u32 fixture_uid,fixture_mask,second_uid,second_mask;
u32 gta3xlwifi_uid_permissions(u32 uid){return uid==fixture_uid?fixture_mask:uid==second_uid?second_mask:0;}
static u32 gta3xlwifi_uid_permissions_features(void){return 7;}
static long gta3xlwifi_uid_permissions_ioctl(unsigned c,unsigned long a){assert(!"unrelated UID store");return -ENOTTY;}
static u32 gta3xlwifi_lna_packet_features(void){return 0;}
static u32 gta3xlwifi_receive_features(void){return 0;}
static u32 gta3xlwifi_egress_features(void){return 0;}
static u32 gta3xlwifi_loopback_features(void){return 0;}
static u32 gta3xlwifi_socket_tables_features(void){return 0;}
static u32 gta3xlwifi_iface_stats_features(void){return 0;}
static u32 gta3xlwifi_packet_stats_features(void){return 0;}
static u32 gta3xlwifi_packet_hooks_features(void){return 0;}
static long gta3xlwifi_lna_ioctl(unsigned c,unsigned long a){assert(!"unrelated LNA store");return -ENOTTY;}
static long gta3xlwifi_loopback_ioctl(unsigned c,unsigned long a){assert(!"unrelated event reader");return -ENOTTY;}
static long gta3xlwifi_iface_stats_ioctl(unsigned c,unsigned long a){assert(!"unrelated interface reader");return -ENOTTY;}
static long gta3xlwifi_packet_stats_ioctl(unsigned c,unsigned long a){assert(!"unrelated packet reader");return -ENOTTY;}
'''+module.read_text()[module.read_text().index('struct runtime_image {'):module.read_text().index('MODULE_LICENSE(')]+'\n'+'\n'.join(m.extract(d,n) for n in ['netpolicy_privileged','netpolicy_open','netpolicy_drop_lease','netpolicy_flush','netpolicy_release','netpolicy_image_ioctl','netpolicy_ioctl'])+r'''
typedef uint8_t u8;typedef uint16_t u16;
struct net{int unused;};
struct gta3xlwifi_packet{struct in6_addr saddr,daddr;u8 ip_version,ip_proto,tcp_flags;__be16 sport,dport;};
struct gta3xlwifi_socket_peer_tuple{u16 family;u8 protocol;__be16 sport,dport;union{struct{__be32 saddr,daddr;}v4;struct{struct in6_addr saddr,daddr;}v6;}address;};
static bool peer_known=true;static u32 peer_uid;static unsigned lookups,emitted;static bool last_allowed;
static bool gta3xlwifi_socket_peer_uid(struct net*n,int index,const struct gta3xlwifi_socket_peer_tuple*t,u32*uid){assert(n&&index==1&&t);++lookups;if(!peer_known)return false;*uid=peer_uid;return true;}
static void loopback_emit(u32 sender,u32 receiver,bool allowed){assert(sender!=receiver);++emitted;last_allowed=allowed;}
'''+m.extract(ld,'loopback_permissions')+'\n'+m.extract(ld,'gta3xlwifi_loopback_blocked')+'\n'
android=A/'packages/modules/Connectivity/bpf/progs/netd.c';nh=android.with_name('netd.h');rt=android.read_text();ht=nh.read_text()
assert 'local_net_blocked_uid_map, HASH, uint32_t, bool, -1000, 25Q2' in rt
aids=A/'system/core/libcutils/include/private/android_filesystem_config.h';assert re.search(r'#define AID_ROOT\s+0\b',aids.read_text()) and re.search(r'#define AID_SYSTEM\s+1000\b',aids.read_text())
chunk=ht[ht.index('// LINT.IfChange(uid_permission_chunk_type)'):ht.index('// LINT.ThenChange(../../common/src/com/android/net/module/util/bpf/UidPermissionChunk.java)')]
start=ht.index('enum LoopbackAccessResult : uint32_t {');end=ht.index('};',start)+2;eventEnum=ht[start:end].replace(' : uint32_t','')
code+='\n'+chunk+'\n'+eventEnum+r'''
#define function static
#define procedure static
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
#define AID_ROOT 0U
#define AID_SYSTEM 1000U
#define BPF_F_CURRENT_NETNS 0
#define TCP_FLAG8_SYN 2
static bool oracle_propagation,oracle_checks,oracle_metrics,oracle_block_value;
static int oracle_block_kind;static unsigned oracle_emitted;static enum LoopbackAccessResult oracle_result;
static bool*bpf_permission_propagation_enabled_map_lookup_elem(const u32*k){assert(!*k);return &oracle_propagation;}
static bool*bpf_local_net_blocked_uid_map_lookup_elem(const u32*k){(void)k;return oracle_block_kind<0?NULL:&oracle_block_value;}
static u32 get_chunk_permissions(u32 uid){return gta3xlwifi_uid_permissions(uid);}
'''+m.extract(ht,'is_system_uid')+'\n'+m.extract(ht,'is_system_or_root')+'\n'+m.extract(rt,'is_local_network_access_blocked')+'\n'+m.extract(rt,'can_force_loopback')+'\n'+m.extract(rt,'uids_have_loopback_permissions')+r'''
typedef struct gta3xlwifi_packet SkbIpPacketData;
struct bpf_sock{u32 unused;};static struct bpf_sock oracle_socket;
struct __sk_buff{void*sk;};
struct bpf_sock_tuple{union{struct{__be32 saddr,daddr;__be16 sport,dport;}ipv4;struct{struct in6_addr saddr,daddr;__be16 sport,dport;}ipv6;};};
typedef struct{u64 cached_at_ns;struct in6_addr daddr;__be16 dport;bool result;}LoopbackCache;
typedef struct{u32 uid;LoopbackCache loopback_cache;}SkStorageValue;
static SkStorageValue oracle_storage;
static bool loopback_checks_enabled(void){return oracle_checks;}
static bool loopback_metrics_enabled(void){return oracle_metrics;}
static struct bpf_sock*bpf_sk_lookup_tcp(struct __sk_buff*s,struct bpf_sock_tuple*t,u32 n,int net,int flags){return peer_known?&oracle_socket:NULL;}
static struct bpf_sock*bpf_sk_lookup_udp(struct __sk_buff*s,struct bpf_sock_tuple*t,u32 n,int net,int flags){return peer_known?&oracle_socket:NULL;}
static SkStorageValue*bpf_sk_storage_get(struct bpf_sock*s,int a,int b){assert(s==&oracle_socket);oracle_storage.uid=peer_uid;return &oracle_storage;}
static void bpf_sk_release(struct bpf_sock*s){assert(s==&oracle_socket);}
static void add_loopback_access_event(u32 sender,u32 receiver,enum LoopbackAccessResult result){assert(sender!=receiver);++oracle_emitted;oracle_result=result;}
static u64 bpf_ktime_get_boot_ns(void){return 1000000000ULL;}
#define LOOPBACK_CACHE_EXPIRATION_NS (10ULL*1000ULL*1000ULL)
'''+m.extract(rt,'should_block_loopback_access')+'\n'+m.extract(rt,'should_block_loopback_access_cached')+r'''
static unsigned cases,lna_comparisons,loop_comparisons;
#define T(x) do{if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}++cases;}while(0)
static struct file owner={1},other={2};
static long io(unsigned cmd,void*p){return netpolicy_ioctl(&owner,cmd,(unsigned long)p);}
static struct gta3xlwifi_runtime_transfer tx(u64 rev,u32 flags,u32 n,void*ids){return(struct gta3xlwifi_runtime_transfer){1,n,flags,0,rev,(uintptr_t)ids};}
static struct gta3xlwifi_runtime_transfer metadata(void){struct gta3xlwifi_runtime_transfer t=tx(0,0,0,NULL);assert(!io(GTA3XLWIFI_RUNTIME_GET,&t));return t;}
static void set_mode(u32 flags,u32 n,u32*ids){struct gta3xlwifi_runtime_transfer t=tx((runtime_current?runtime_current->revision:0)+1,flags,n,n?ids:NULL);long result=io(GTA3XLWIFI_RUNTIME_SET,&t);if(result)fprintf(stderr,"SET failed result=%ld rev=%llu flags=%u count=%u held=%d\n",result,(unsigned long long)t.revision,t.flags,t.count,gta3xlwifi_netpolicy_held());assert(!result);}
int main(void){
 T(sizeof(struct gta3xlwifi_runtime_transfer)==32&&GTA3XLWIFI_RUNTIME_GET==0xc0206760&&GTA3XLWIFI_RUNTIME_SET==0x40206761);
 T(!gta3xlwifi_runtime_configured()&&gta3xlwifi_runtime_loopback_flags()==3&&gta3xlwifi_runtime_features()==16384);
 struct gta3xlwifi_runtime_transfer t=tx(1,7,0,NULL);T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-ENOTCONN);T(netpolicy_open(NULL,&owner)==0);T(io(0x6762,NULL)==-ENOTTY);T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==-EAGAIN&&gta3xlwifi_netpolicy_held());t=metadata();T(!t.revision&&!t.status&&!t.flags&&!t.count);
 t=tx(0,7,0,NULL);T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EINVAL);set_mode(7,0,NULL);T(gta3xlwifi_runtime_configured());T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==0&&!gta3xlwifi_netpolicy_held());t=tx(2,0,0,NULL);T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EBUSY);T(io(GTA3XLWIFI_NETPOLICY_HOLD,NULL)==0);
 for(unsigned cmd=0;cmd<2;cmd++){unsigned c=cmd?GTA3XLWIFI_RUNTIME_SET:GTA3XLWIFI_RUNTIME_GET;t=tx(2,0,0,NULL);task.euid=1000;T(io(c,&t)==-EPERM);task.euid=0;task.admin=false;T(io(c,&t)==-EPERM);task.admin=true;task.tgid=&child_pid;T(io(c,&t)==-EPERM);task.tgid=&parent_pid;T(netpolicy_ioctl(&other,c,(unsigned long)&t)==-EPERM);T(io(c,NULL)==-EFAULT);}
 u32 ids[]={0,1000,10001,110001,2147483647};set_mode(5,5,ids);t=metadata();T(t.count==5&&t.flags==5&&t.status==1);u32 read_ids[1000]={0};t=tx(t.revision,0,1000,read_ids);T(!io(GTA3XLWIFI_RUNTIME_GET,&t)&&t.count==5&&!memcmp(read_ids,ids,sizeof(ids)));t=tx(t.revision,0,1,read_ids);T(io(GTA3XLWIFI_RUNTIME_GET,&t)==-ENOSPC&&t.count==5);t=tx(1,0,1000,read_ids);T(io(GTA3XLWIFI_RUNTIME_GET,&t)==-ESTALE);
 u64 revision=runtime_current->revision;unsigned graces=rcu_graces;t=tx(revision,5,5,ids);T(!io(GTA3XLWIFI_RUNTIME_SET,&t)&&rcu_graces==graces);task.tgid=&child_pid;T(netpolicy_flush(&owner,NULL)==0&&gta3xlwifi_runtime_configured());task.tgid=&parent_pid;T(netpolicy_flush(&owner,NULL)==0&&!gta3xlwifi_runtime_configured());T(netpolicy_open(NULL,&owner)==0&&!gta3xlwifi_runtime_configured());t=metadata();T(t.revision==revision&&t.flags==5&&t.status==0);T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==-EAGAIN);t=tx(revision,5,5,ids);T(!io(GTA3XLWIFI_RUNTIME_SET,&t)&&gta3xlwifi_runtime_configured()&&rcu_graces==graces);
 for(unsigned bad=0;bad<8;bad++){t=tx(revision+1,5,5,ids);u32 saved=ids[1];switch(bad){case 0:t.version=2;break;case 1:t.flags=8;break;case 2:t.status=1;break;case 3:t.count=1001;break;case 4:t.entries=0;break;case 5:t.revision=revision+2;break;case 6:ids[1]=ids[0];break;case 7:ids[1]=UINT32_MAX;break;}T(io(GTA3XLWIFI_RUNTIME_SET,&t)==(bad==5?-ESTALE:-EINVAL)&&runtime_current->revision==revision);ids[1]=saved;}
 t=tx(revision+1,0,0,NULL);alloc_fail=1;T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-ENOMEM&&runtime_current->revision==revision);alloc_fail=0;from_fail=from_calls+1;T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EFAULT);from_fail=0;t=tx(revision+1,5,5,ids);from_fail=from_calls+2;T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EFAULT&&runtime_current->revision==revision);from_fail=0;t=tx(0,0,0,NULL);to_fail=to_calls+1;T(io(GTA3XLWIFI_RUNTIME_GET,&t)==-EFAULT);to_fail=0;
 const u32 uids[]={0,1,999,1000,1001,9999,10000,10001,65534,99999,100000,101000,109999,110000,110001,2147483647};
 for(u32 flags=0;flags<8;flags++)for(int blocked=-1;blocked<=1;blocked++){
  oracle_propagation=flags&4;oracle_block_kind=blocked;oracle_block_value=blocked==1;set_mode(flags,blocked==1?16:0,(u32*)uids);T(metadata().flags==flags);
  for(unsigned u=0;u<16;u++)for(u32 mask=0;mask<128;mask++){fixture_uid=uids[u];fixture_mask=mask;second_uid=UINT32_MAX;second_mask=0;assert(gta3xlwifi_runtime_lna_needs_check(uids[u])==is_local_network_access_blocked(uids[u]));++lna_comparisons;}
 }
 struct net net={0};struct gta3xlwifi_packet packet={.ip_version=4,.ip_proto=IPPROTO_UDP,.tcp_flags=2};struct __sk_buff skb={0};const u32 pairs[][2]={{10001,110001},{10001,110002},{110001,10001},{0,110001},{101000,110001},{10001,10002}};
 for(u32 flags=0;flags<8;flags++){set_mode(flags,0,NULL);oracle_checks=flags&1;oracle_metrics=flags&2;
  for(unsigned pair=0;pair<6;pair++)for(u32 senderMask=0;senderMask<128;senderMask++)for(u32 receiverMask=0;receiverMask<128;receiverMask++){
   fixture_uid=pairs[pair][0];second_uid=peer_uid=pairs[pair][1];fixture_mask=senderMask;second_mask=receiverMask;peer_known=true;emitted=oracle_emitted=lookups=0;
   bool expected=should_block_loopback_access_cached(&packet,&skb,fixture_uid);bool actual=gta3xlwifi_loopback_blocked(&net,1,fixture_uid,&packet);
   assert(actual==expected&&emitted==oracle_emitted&&(!emitted||(last_allowed==(oracle_result==LOOPBACK_ACCESS_ALLOWED)))&&(flags&3?lookups==1:lookups==0));++loop_comparisons;
  }
  for(unsigned fault=0;fault<6;fault++){packet.ip_version=4;packet.ip_proto=IPPROTO_UDP;packet.tcp_flags=2;peer_known=true;peer_uid=second_uid=110002;fixture_uid=10001;fixture_mask=second_mask=0;unsigned index=1;switch(fault){case 0:peer_known=false;break;case 1:peer_uid=fixture_uid;break;case 2:packet.ip_version=0;break;case 3:packet.ip_proto=IPPROTO_GRE;break;case 4:packet.ip_proto=IPPROTO_TCP;packet.tcp_flags=0;break;case 5:index=17;break;}emitted=0;T(!gta3xlwifi_loopback_blocked(&net,index,fixture_uid,&packet)&&!emitted);}
  packet.ip_version=4;packet.ip_proto=IPPROTO_UDP;packet.tcp_flags=2;
 }
 runtime_current->revision=UINT64_MAX;t=tx(1,7,0,NULL);T(io(GTA3XLWIFI_RUNTIME_SET,&t)==-EOVERFLOW);t=tx(UINT64_MAX,runtime_current->flags,0,NULL);T(!io(GTA3XLWIFI_RUNTIME_SET,&t));T(netpolicy_release(NULL,&owner)==0&&!gta3xlwifi_runtime_configured()&&gta3xlwifi_netpolicy_held());
 printf("passed_cases=%u LNA_comparisons=%u loopback_comparisons=%u\n",cases,lna_comparisons,loop_comparisons);return 0;
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-Wno-unused-variable','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=180,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);match=re.fullmatch(r'passed_cases=(\d+) LNA_comparisons=49152 loopback_comparisons=786432\n',x.stdout);assert match
paths=[Path(__file__),h,legacy,module,driver,loop,local,header,android,nh,aids,O/'test.c',*[p for p in inc.glob('*.h')]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_A17_LNA_comparisons':49152,'actual_A17_loopback_comparisons':786432,'unconfigured_lease_release_rejected':True,'strict_root_file_TGID_held_auth':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
