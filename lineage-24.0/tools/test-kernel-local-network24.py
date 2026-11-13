#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual immutable LNA store/trie/decision and lease dispatch C with fault fixtures.

Actual selected Android17 permission and LPM decision expressions are the oracle;
map lookup fixtures use an independent bitwise linear LPM implementation. RCU,
alloc/copies/credentials are fixtures, not kernel/packet/runtime readiness.
"""
import argparse,ast,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','uid-source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();U=a.uid_source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
legacy=Path(__file__).with_name('test-kernel-uid-permissions24.py');tree=ast.parse(legacy.read_text());prefix=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='prefix' for t in n.targets))
prefix=prefix.replace('static int alloc_fail,','static int alloc_fail,alloc_attempt,alloc_fail_at,').replace('if(alloc_fail)return NULL;','if(++alloc_attempt==alloc_fail_at||alloc_fail)return NULL;')
prefix+='''\n#include <netinet/in.h>\n#include <linux/netfilter/gta3xlwifi_local_network.h>\ntypedef uint8_t u8;typedef uint16_t u16;typedef uint16_t __be16;\n#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))\n'''
image=S/'net/netfilter/gta3xlwifi_local_network.c';driver=S/'net/netfilter/gta3xlwifi_netpolicy.c';uid=U/'net/netfilter/gta3xlwifi_uid_permissions.c';c=image.read_text();d=driver.read_text();uc=uid.read_text();reference=A/'packages/modules/Connectivity/bpf/progs/netd.c';rh=reference.with_name('netd.h');r=reference.read_text();h=rh.read_text()
if 'gta3xlwifi_lna_packet_features()' in d:
 prefix+='\nstatic u32 gta3xlwifi_lna_packet_features(void){return 0;} /* registration tested separately */\n'
metrics_header=S/'include/uapi/linux/netfilter/gta3xlwifi_loopback.h'
if metrics_header.exists():
 prefix+='\n#include <linux/netfilter/gta3xlwifi_loopback.h>\nstatic u32 gta3xlwifi_loopback_features(void){return 0;}\nstatic long gta3xlwifi_loopback_ioctl(unsigned int cmd,unsigned long arg){(void)cmd;(void)arg;assert(!"legacy primitive test entered loopback stream");return -ENOTTY;}\n'
 exported_metrics=O/'include/linux/netfilter/gta3xlwifi_loopback.h';exported_metrics.parent.mkdir(parents=True,exist_ok=True);exported_metrics.write_bytes(metrics_header.read_bytes())
if 'gta3xlwifi_receive_features()' in d:
 prefix+='\nstatic u32 gta3xlwifi_receive_features(void){return 0;} /* receive registration tested separately */\n'
iface_header=S/'include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h'
if iface_header.exists():
 prefix+='\n#include <linux/netfilter/gta3xlwifi_iface_stats.h>\nstatic unsigned gta3xlwifi_iface_stats_features(void){return 0;} /* actual producer tested separately */\nstatic long gta3xlwifi_iface_stats_ioctl(unsigned int c,unsigned long a){(void)c;(void)a;assert(!"legacy fixture entered interface snapshot");return -ENOTTY;}\n'
 exported_iface=O/'include/linux/netfilter/gta3xlwifi_iface_stats.h';exported_iface.parent.mkdir(parents=True,exist_ok=True);exported_iface.write_bytes(iface_header.read_bytes())
packet_header=S/'include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h'
if packet_header.exists():
 prefix+='\n#include <linux/netfilter/gta3xlwifi_packet_stats.h>\nstatic unsigned gta3xlwifi_packet_stats_features(void){return 0;} /* actual storage tested separately */\nstatic long gta3xlwifi_packet_stats_ioctl(unsigned int c,unsigned long a){(void)c;(void)a;assert(!"legacy fixture entered packet storage");return -ENOTTY;}\n'
 exported_packet=O/'include/linux/netfilter/gta3xlwifi_packet_stats.h';exported_packet.parent.mkdir(parents=True,exist_ok=True);exported_packet.write_bytes(packet_header.read_bytes())
if 'gta3xlwifi_socket_tables_features()' in d:
 prefix+='\nstatic u32 gta3xlwifi_socket_tables_features(void){return 0;} /* real table registration tested separately */\n'
if 'gta3xlwifi_egress_features()' in d:
 prefix+='\nstatic u32 gta3xlwifi_egress_features(void){return 0;} /* output hooks tested separately */\n'
globals=d[d.index('static DEFINE_MUTEX('):d.index('static bool netpolicy_privileged(')]
store=uc[uc.index('struct gta3xlwifi_uid_image {'):uc.index('MODULE_LICENSE(')]+c[c.index('#define LNA_NONE'):c.index('MODULE_LICENSE(')]
functions='\n'.join(m.extract(d,n) for n in ['netpolicy_privileged','netpolicy_open','netpolicy_drop_lease','netpolicy_flush','netpolicy_release','netpolicy_image_ioctl','netpolicy_ioctl'])
# Only key typedefs and actual A17 functions are copied; lookup algorithm is independent.
def declaration(name):
 end=h.index('} '+name+';')+len('} '+name+';');start=h.rfind('typedef struct {',0,end);return h[start:end]
oracle=r'''
#define function static
#define AID_ROOT 0U
#define AID_SYSTEM 1000U
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
'''+re.search(r'#define PERMISSION_BIT_ACCESS_LOCAL_NETWORK[^\n]+',h).group()+'\n'+declaration('LocalNetAccessKey')+'\n'+declaration('LocalNetUidHostAllowlistKey')+r'''
static struct gta3xlwifi_lna_entry *onetwork,*ohost;
static u32 oncount,ohcount;
static bool oracle_propagation=true,omvalue,ohvalue;
static const struct gta3xlwifi_lna_entry* slow_lpm(const struct gta3xlwifi_lna_entry*e,u32 count,const u8*key){
 const struct gta3xlwifi_lna_entry*best=NULL;
 for(u32 i=0;i<count;i++){
  bool equal=true;for(u32 bit=0;bit<e[i].prefix_bits;bit++)if(((key[bit/8]>>(7-bit%8))&1)!=((e[i].key[bit/8]>>(7-bit%8))&1)){equal=false;break;}
  if(equal&&(!best||e[i].prefix_bits>best->prefix_bits))best=&e[i];
 }return best;
}
static bool* bpf_local_net_access_map_lookup_elem(const LocalNetAccessKey*k){assert(k->lpm_bitlen==192);const struct gta3xlwifi_lna_entry*e=slow_lpm(onetwork,oncount,(const u8*)&k->if_index);if(!e)return NULL;omvalue=e->allowed;return &omvalue;}
static bool* bpf_local_net_uid_host_allowlist_map_lookup_elem(const LocalNetUidHostAllowlistKey*k){assert(k->lpm_bitlen==192);const struct gta3xlwifi_lna_entry*e=slow_lpm(ohost,ohcount,(const u8*)&k->uid);if(!e)return NULL;ohvalue=e->allowed;return &ohvalue;}
static bool* bpf_permission_propagation_enabled_map_lookup_elem(const u32*k){assert(*k==0);return &oracle_propagation;}
static bool* bpf_local_net_blocked_uid_map_lookup_elem(const u32*k){(void)k;assert(!"unselected old permission branch");return NULL;}
static u32 get_chunk_permissions(u32 uid){return gta3xlwifi_uid_permissions(uid);}
'''+m.extract(h,'is_system_uid')+'\n'+m.extract(h,'is_system_or_root')+'\n'+m.extract(r,'is_local_network_access_blocked')+'\n'+m.extract(r,'is_local_net_access_allowed')+r'''
static bool oracle_blocked(u32 uid,u32 index,const struct in6_addr*remote,u16 protocol,__be16 port){
 LocalNetAccessKey key={.lpm_bitlen=192,.if_index=index,.remote_ip6=*remote,.protocol=protocol,.remote_port=port};
 return is_local_network_access_blocked(uid)&&!is_local_net_access_allowed(&key,uid);
}
'''
tests=r'''
static unsigned cases,comparisons;
#define T(x) do{if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}++cases;}while(0)
static struct file owner={1},foreign={2};
static long io(unsigned cmd,void*arg){from_calls=to_calls=alloc_attempt=0;return netpolicy_ioctl(&owner,cmd,(unsigned long)arg);}
static struct gta3xlwifi_lna_transfer tx(u64 rev,u32 nc,void*n,u32 hc,void*host){return(struct gta3xlwifi_lna_transfer){1,nc,hc,0,rev,(uintptr_t)n,(uintptr_t)host};}
static int compare(const void*a,const void*b){const struct gta3xlwifi_lna_entry*x=a,*y=b;if(x->prefix_bits!=y->prefix_bits)return x->prefix_bits<y->prefix_bits?-1:1;return memcmp(x->key,y->key,24);}
static u32 state=0x12345678;static u32 random32(void){state^=state<<13;state^=state>>17;state^=state<<5;return state;}
static void reference_image(struct gta3xlwifi_lna_entry*n,u32 nc,struct gta3xlwifi_lna_entry*host,u32 hc){onetwork=n;oncount=nc;ohost=host;ohcount=hc;}
static void check_decision(u32 uid,u32 index,const struct in6_addr*ip,u16 proto,__be16 port){assert(gta3xlwifi_lna_blocked(uid,index,ip,proto,port)==oracle_blocked(uid,index,ip,proto,port));++comparisons;}
int main(void){
 _Static_assert(sizeof(LocalNetAccessKey)==28&&sizeof(LocalNetUidHostAllowlistKey)==28,"actual A17 layouts");
 T(sizeof(struct gta3xlwifi_lna_transfer)==40&&sizeof(struct gta3xlwifi_lna_entry)==32);
 T(GTA3XLWIFI_LNA_SET_IMAGE==0x40286757&&GTA3XLWIFI_LNA_GET_IMAGE==0xc0286758);
 struct gta3xlwifi_lna_entry n[2]={{.prefix_bits=0,.allowed=0},{.prefix_bits=192,.allowed=1}},host[1]={{.prefix_bits=192,.allowed=1}};
 u32 uidval=10001,index=7;u16 proto=17;__be16 port=htons(5353);struct in6_addr ip={0};ip.s6_addr[0]=0x20;ip.s6_addr[1]=1;ip.s6_addr[2]=0x0d;ip.s6_addr[3]=0xb8;
 memcpy(n[1].key,&index,4);memcpy(n[1].key+4,&ip,16);memcpy(n[1].key+20,&proto,2);memcpy(n[1].key+22,&port,2);
 memcpy(host[0].key,&uidval,4);memcpy(host[0].key+4,&index,4);memcpy(host[0].key+8,&ip,16);
 struct gta3xlwifi_lna_transfer t=tx(1,2,n,1,host),q=tx(0,0,NULL,0,NULL);
 T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ENOTCONN);T(netpolicy_open(NULL,&owner)==0);T(io(GTA3XLWIFI_UID_FEATURES,NULL)==15&&gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==0&&q.revision==0&&q.network_count==0&&q.host_count==0);
 for(unsigned i=0;i<2;i++){unsigned cmd=i?GTA3XLWIFI_LNA_GET_IMAGE:GTA3XLWIFI_LNA_SET_IMAGE;
  task.euid=1000;T(io(cmd,&t)==-EPERM);task.euid=0;task.admin=false;T(io(cmd,&t)==-EPERM);task.admin=true;
  task.tgid=&child_pid;T(io(cmd,&t)==-EPERM);task.tgid=&parent_pid;T(netpolicy_ioctl(&foreign,cmd,(unsigned long)&t)==-EPERM);
 }
 T(io(GTA3XLWIFI_LNA_SET_IMAGE,NULL)==-EFAULT);T(io(GTA3XLWIFI_LNA_GET_IMAGE,NULL)==-EFAULT);T(io(0x6757,NULL)==-ENOTTY);T(io(0x6759,NULL)==-ENOTTY);
 T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0&&lna_current->revision==1&&rcu_graces==1);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0&&rcu_graces==1);
 reference_image(n,2,host,1);check_decision(10001,index,&ip,proto,port);check_decision(10002,index,&ip,proto,port);check_decision(10002,index,&ip,6,port);check_decision(10001,index,&ip,6,port);
 T(!gta3xlwifi_lna_blocked(10001,index,&ip,6,port));T(gta3xlwifi_lna_blocked(10002,index,&ip,6,port));
 t.revision=2;
 for(int fail=1;fail<=5;fail++){alloc_fail_at=fail;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ENOMEM&&lna_current->revision==1&&rcu_graces==1);}alloc_fail_at=0;
 for(int fail=1;fail<=3;fail++){from_fail=fail;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EFAULT&&lna_current->revision==1&&rcu_graces==1);}from_fail=0;
 t.version=2;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.version=1;t.reserved=1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.reserved=0;
 t.network_count=1001;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.network_count=2;t.host_count=1001;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.host_count=1;
 t.network_entries=0;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);t.network_entries=(uintptr_t)n;
 n[1].prefix_bits=193;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[1].prefix_bits=192;n[1].allowed=2;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[1].allowed=1;
 for(unsigned i=0;i<3;i++){n[1].reserved[i]=1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[1].reserved[i]=0;}
 n[0].key[23]=1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[0].key[23]=0;
 struct gta3xlwifi_lna_entry saved=n[1];n[1]=n[0];T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EINVAL);n[1]=saved;
 t.revision=0;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ESTALE);t.revision=3;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ESTALE);t.revision=1;n[0].allowed=1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-ESTALE);n[0].allowed=0;
 struct gta3xlwifi_lna_entry outn[3],outh[2];memset(outn,0x5a,sizeof(outn));memset(outh,0x5a,sizeof(outh));
 q=tx(0,0,NULL,0,NULL);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==0&&q.revision==1&&q.network_count==2&&q.host_count==1);
 q=tx(0,3,outn,2,outh);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==-ESTALE&&outn[0].prefix_bits==0x5a5a5a5a);
 q=tx(1,1,outn,1,outh);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==-ENOSPC&&q.network_count==2&&outn[0].prefix_bits==0x5a5a5a5a);
 q=tx(1,3,outn,2,outh);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==0&&q.network_count==2&&q.host_count==1&&!memcmp(n,outn,sizeof(n))&&!memcmp(host,outh,sizeof(host)));
 for(int fail=1;fail<=3;fail++){to_fail=fail;q=tx(1,3,outn,2,outh);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==-EFAULT&&lna_current->revision==1);}to_fail=0;
 T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==0&&!gta3xlwifi_netpolicy_held());t.revision=2;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EBUSY&&lna_current->revision==1);q=tx(0,0,NULL,0,NULL);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==0&&!gta3xlwifi_netpolicy_held());T(io(GTA3XLWIFI_NETPOLICY_HOLD,NULL)==0);
 // Exhaustive actual A17 permission expression, literal vs per-user core UIDs.
 struct gta3xlwifi_lna_entry deny={.prefix_bits=0,.allowed=0};t=tx(2,1,&deny,0,NULL);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);reference_image(&deny,1,NULL,0);
 const u32 uids[]={0,1,1000,9999,10001,65534,100001,101000,110001,2147483647};
 for(unsigned u=0;u<sizeof(uids)/sizeof(uids[0]);u++)for(u32 mask=0;mask<128;mask++){
  struct gta3xlwifi_uid_permission_entry permission={uids[u],mask};struct gta3xlwifi_uid_permission_transfer ut={1,mask?1:0,uid_image?uid_image->revision+1:1,mask?(uintptr_t)&permission:0};assert(io(GTA3XLWIFI_UID_SET_IMAGE,&ut)==0);
  check_decision(uids[u],index,&ip,proto,port);
 }
 T(gta3xlwifi_lna_blocked(10001,index,NULL,proto,port));
 struct gta3xlwifi_uid_permission_transfer clear={1,0,uid_image->revision+1,0};assert(io(GTA3XLWIFI_UID_SET_IMAGE,&clear)==0);

 // Actual Java producer uses a64-bit UID/interface wildcard, not only192 hosts.
 struct gta3xlwifi_lna_entry wide[2]={{.prefix_bits=64,.allowed=1},{.prefix_bits=192,.allowed=0}};
 memcpy(wide[0].key,&uidval,4);memcpy(wide[0].key+4,&index,4);
 memcpy(wide[1].key,wide[0].key,24);memcpy(wide[1].key+8,&ip,16);
 t=tx(lna_current->revision+1,1,&deny,2,wide);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);reference_image(&deny,1,wide,2);
 T(gta3xlwifi_lna_blocked(uidval,index,&ip,proto,port));check_decision(uidval,index,&ip,proto,port);
 struct in6_addr other=ip;other.s6_addr[15]^=1;T(!gta3xlwifi_lna_blocked(uidval,index,&other,proto,port));check_decision(uidval,index,&other,proto,port);
 T(gta3xlwifi_lna_blocked(uidval,index+1,&other,proto,port));check_decision(uidval,index+1,&other,proto,port);
 T(gta3xlwifi_lna_blocked(uidval+1,index,&other,proto,port));check_decision(uidval+1,index,&other,proto,port);
 struct in6_addr mapped={0};mapped.s6_addr[10]=mapped.s6_addr[11]=255;mapped.s6_addr[12]=192;mapped.s6_addr[15]=1;T(!gta3xlwifi_lna_blocked(uidval,index,&mapped,proto,port));check_decision(uidval,index,&mapped,proto,port);
 wide[0].allowed=0;wide[1].allowed=1;t.revision=lna_current->revision+1;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);
 T(!gta3xlwifi_lna_blocked(uidval,index,&ip,proto,port));T(gta3xlwifi_lna_blocked(uidval,index,&other,proto,port));check_decision(uidval,index,&ip,proto,port);check_decision(uidval,index,&other,proto,port);
 // Independent slow bit-loop oracle across compressed branch/ancestor/sibling paths.
 struct gta3xlwifi_lna_entry many[1000],hosts[1000];
 for(unsigned round=0;round<64;round++){
  u32 nc=round==0?1000:random32()%1001,hc=round==0?1000:random32()%1001;
  for(unsigned which=0;which<2;which++){
   struct gta3xlwifi_lna_entry*e=which?hosts:many;u32 count=which?hc:nc;
   for(u32 i=0;i<count;i++){memset(&e[i],0,sizeof(e[i]));e[i].prefix_bits=random32()%193;e[i].allowed=random32()&1;for(unsigned b=0;b<24;b++)e[i].key[b]=random32();lna_canonical(e[i].key,e[i].prefix_bits);}
   qsort(e,count,sizeof(*e),compare);u32 unique=0;for(u32 i=0;i<count;i++)if(!unique||compare(&e[unique-1],&e[i]))e[unique++]=e[i];if(which)hc=unique;else nc=unique;
  }
  t=tx(lna_current->revision+1,nc,nc?many:NULL,hc,hc?hosts:NULL);assert(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);reference_image(many,nc,hosts,hc);
  assert(lna_current->network.nodes_count<=2*nc&&lna_current->host.nodes_count<=2*hc);
  for(unsigned i=0;i<4096;i++){
   u8 key[24];for(unsigned b=0;b<24;b++)key[b]=random32();if(nc&&i%2==0){u32 e=random32()%nc;memcpy(key,many[e].key,24);for(u32 bit=many[e].prefix_bits;bit<192;bit++)if(random32()&1)key[bit/8]^=1U<<(7-bit%8);}
   u32 queryIndex;u16 queryProto;__be16 queryPort;memcpy(&queryIndex,key,4);memcpy(&ip,key+4,16);memcpy(&queryProto,key+20,2);memcpy(&queryPort,key+22,2);
   check_decision(uids[i%10],queryIndex,&ip,queryProto,queryPort);
   bool actual=false;const struct gta3xlwifi_lna_entry*expected=slow_lpm(many,nc,key);bool found=lna_lookup(&lna_current->network,key,&actual);assert(found==!!expected&&(!found||actual==!!expected->allowed));++comparisons;
   expected=slow_lpm(hosts,hc,key);found=lna_lookup(&lna_current->host,key,&actual);assert(found==!!expected&&(!found||actual==!!expected->allowed));++comparisons;
  }
 }
 // Every prefix boundary plus nested ancestor precedence, including0/192.
 for(u32 bits=0;bits<=192;bits++){
  memset(many,0,2*sizeof(*many));many[0].allowed=1;many[1].prefix_bits=bits;many[1].allowed=0;memset(many[1].key,0xaa,24);lna_canonical(many[1].key,bits);u32 count=bits?2:1;if(!bits)many[0].allowed=0;
  t=tx(lna_current->revision+1,count,many,0,NULL);assert(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);
  bool value=true;assert(lna_lookup(&lna_current->network,many[1].key,&value)&&!value);++comparisons;
 }
 lna_current->revision=UINT64_MAX;t=tx(UINT64_MAX,lna_current->network.count,lna_current->network.entries,0,NULL);T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==0);t.revision=0;T(io(GTA3XLWIFI_LNA_SET_IMAGE,&t)==-EOVERFLOW);
 T(netpolicy_flush(&owner,NULL)==0&&gta3xlwifi_netpolicy_held()&&parent_pid.refs==0);T(io(GTA3XLWIFI_LNA_GET_IMAGE,&q)==-ENOTCONN);T(netpolicy_release(NULL,&owner)==0);
 lna_free(lna_current);lna_current=NULL;vfree(uid_image);uid_image=NULL;T(allocs==frees&&!publication_pending&&!rcu_depth);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
'''
code='\n'.join([prefix,globals,store,functions,oracle,tests]);(O/'test.c').write_text(code);inputs=[Path(__file__),helper,legacy,image,driver,uid,reference,rh]
for root,name in [(U,'gta3xlwifi_uid_permissions.h'),(U,'gta3xlwifi_netpolicy.h'),(S,'gta3xlwifi_local_network.h')]:
 src=root/'include/uapi/linux/netfilter'/name;dst=O/'include/linux/netfilter'/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes());inputs +=[src,dst]
cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=120);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',x.stdout);assert match and int(match[1])>=60 and int(match[2])>=787000
inputs.append(O/'test.c');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'comparisons':int(match[2]),'command':cmd,'inputs_sha256':{str(p):sha(p) for p in inputs},'kernel_runtime_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual store/trie/decision/dispatch C + selected A17 oracle, fatal UBSan')
