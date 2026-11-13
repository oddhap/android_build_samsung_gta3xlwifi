#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute actual UID image/lease dispatch/create C with fault and lifetime fixtures.

Actual sparse store, binary search, generation, ioctl authorization and inet-check
bodies execute with pthread owner mutex. RCU, user copies, allocation, credentials,
network grace and socket cleanup are fixtures; not kernel/device packet evidence.
The selected Android17 NoInternet expression supplies the independent value oracle.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
image=S/'net/netfilter/gta3xlwifi_uid_permissions.c';driver=S/'net/netfilter/gta3xlwifi_netpolicy.c';c=image.read_text();d=driver.read_text()
reference=A/'packages/modules/Connectivity/bpf/progs/netd.c';rh=reference.with_name('netd.h');r=reference.read_text();h=rh.read_text()
branch=re.search(r'return \(get_chunk_permissions\(uid\) & PERMISSION_BIT_NO_INTERNET\)\s*\? BPF_DISALLOW\s*:\s*BPF_ALLOW;',m.extract(r,'inet_socket_create')).group()
bit=re.search(r'#define PERMISSION_BIT_NO_INTERNET\s+[^\n]+',h).group()
# Verify both actual late inet hooks. Execute the common actual tail in fixtures.
tails=[];inputs=[image,driver,reference,rh,helper,Path(__file__)]
for path,name in [('net/ipv4/af_inet.c','inet_create'),('net/ipv6/af_inet6.c','inet6_create')]:
 file=S/path;inputs.append(file);raw=file.read_text();raw=re.sub(r'#ifdef CONFIG_MPTCP\nint inet_create\([^\n]+\n#else\n', '', raw, flags=re.S) if name=='inet_create' else raw;raw=re.sub(r'\n#endif\n(?=\{)', '\n', raw);f=m.extract(raw,name)
 tail=f[f.index('\tif (sk->sk_prot->init) {'):f.index('out:\n\treturn err;')]
 assert tail.count('gta3xlwifi_uid_inet_create_check()')==1 and 'if (!kern)' in tail
 assert '#include <net/gta3xlwifi_uid_permissions.h>' in file.read_text()
 tails.append('static int tail'+str(len(tails))+'(struct fake_sock*sk,bool kern){int err=0;'+tail+'out:\nreturn err;}\n')
prefix=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <linux/netfilter/gta3xlwifi_uid_permissions.h>
#include <linux/netfilter/gta3xlwifi_netpolicy.h>
typedef uint64_t u64;typedef uint32_t u32;
#define __rcu
#define __user
#define EXPORT_SYMBOL_GPL(x)
#define CONFIG_INET 1
#define CONFIG_IPV6 1
#define IS_ENABLED(x) (x)
#define BUILD_BUG_ON(x) _Static_assert(!(x),#x)
#define GLOBAL_ROOT_UID 0
#define CAP_NET_ADMIN 12
#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(n) assert(pthread_mutex_lock(n)==0)
#define mutex_unlock(n) assert(pthread_mutex_unlock(n)==0)
#define WRITE_ONCE(p,v) __atomic_store_n(&(p),(v),__ATOMIC_RELAXED)
#define READ_ONCE(p) __atomic_load_n(&(p),__ATOMIC_RELAXED)
#define smp_store_release(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
struct file{int id;};struct inode{int id;};typedef void* fl_owner_t;
struct pid{int refs;};struct task{u32 uid,euid;bool admin;struct pid*tgid;};
static struct pid parent_pid,child_pid;static struct task task={0,0,true,&parent_pid};
#define current (&task)
static int init_user_ns;
static u32 current_euid(void){return task.euid;}
static u32 current_uid(void){return task.uid;}
static bool uid_eq(u32 a,u32 b){return a==b;}
static u32 from_kuid(const void*n,u32 uid){assert(n==&init_user_ns);return uid;}
static bool ns_capable(const void*n,int c){assert(n==&init_user_ns&&c==CAP_NET_ADMIN);return task.admin;}
static struct pid*task_tgid(struct task*t){return t->tgid;}
static struct pid*get_pid(struct pid*p){++p->refs;return p;}
static void put_pid(struct pid*p){assert(p->refs>0);--p->refs;}
static unsigned network_graces,rcu_graces,rcu_depth,allocs,frees;
static int alloc_fail,from_calls,to_calls,from_fail,to_fail;
static void* last_publication;static bool publication_pending;
static void synchronize_net(void){++network_graces;}
static void* vzalloc(size_t n){if(alloc_fail)return NULL;void*p=calloc(1,n);assert(p);++allocs;return p;}
static void vfree(void*p){if(p){assert(!publication_pending);++frees;free(p);}}
static int copy_from_user(void*d,const void*s,size_t n){if(++from_calls==from_fail)return 1;memcpy(d,s,n);return 0;}
static int copy_to_user(void*d,const void*s,size_t n){if(++to_calls==to_fail)return 1;memcpy(d,s,n);return 0;}
static void rcu_read_lock(void){++rcu_depth;}
static void rcu_read_unlock(void){assert(rcu_depth);--rcu_depth;}
#define rcu_dereference(p) (assert(rcu_depth),(p))
#define rcu_dereference_protected(p,c) (assert(c),(p))
#define rcu_assign_pointer(p,v) do{assert(!publication_pending);(p)=(v);last_publication=(v);publication_pending=true;}while(0)
static void synchronize_rcu(void){assert(publication_pending&&last_publication&&!rcu_depth);publication_pending=false;++rcu_graces;}
'''
store=c[c.index('struct gta3xlwifi_uid_image {'):c.index('MODULE_LICENSE(')]
globals=d[d.index('static DEFINE_MUTEX('):d.index('static bool netpolicy_privileged(')]
functions='\n'.join(m.extract(d,n) for n in ['netpolicy_privileged','netpolicy_open','netpolicy_drop_lease','netpolicy_flush','netpolicy_release','netpolicy_image_ioctl','netpolicy_ioctl'])
# Tiny oracle map is a fixture; the actual branch/bit expression is unchanged.
oracle=bit+'\nstatic u32 oracle_uid,oracle_mask;\nstatic u32 get_chunk_permissions(u32 uid){return uid==oracle_uid?oracle_mask:0;}\n#define BPF_ALLOW 1\n#define BPF_DISALLOW 0\nstatic int oracle(u32 uid){'+branch+'}\n'
fixture=r'''
struct fake_proto{int(*init)(void*);};struct fake_sock{struct fake_proto*sk_prot;};
static unsigned release_count,init_calls;static int init_error;
static void sk_common_release(struct fake_sock*s){assert(s);++release_count;}
static int proto_init(void*s){assert(s);++init_calls;return init_error;}
'''
tests=r'''
static unsigned cases,comparisons;
#define T(x) do{if(!(x)){fprintf(stderr,"failed line %d: %s\n",__LINE__,#x);abort();}++cases;}while(0)
static struct file owner={1},other={2};
static long io(unsigned cmd,void*p){from_calls=to_calls=0;return netpolicy_ioctl(&owner,cmd,(unsigned long)p);}
static struct gta3xlwifi_uid_permission_transfer tx(u64 revision,u32 count,void*e){return (struct gta3xlwifi_uid_permission_transfer){1,count,revision,(uintptr_t)e};}
static u64 revision(void){return uid_image?uid_image->revision:0;}
static void unchanged(u64 rev,unsigned graces){assert(revision()==rev&&rcu_graces==graces&&gta3xlwifi_netpolicy_held());}
int main(void){
 T(sizeof(struct gta3xlwifi_uid_permission_transfer)==24&&offsetof(struct gta3xlwifi_uid_permission_transfer,entries)==16);
 T(sizeof(struct gta3xlwifi_uid_permission_entry)==8&&GTA3XLWIFI_UID_FEATURES==0x6754);
 T(_IOC_SIZE(GTA3XLWIFI_UID_SET_IMAGE)==24&&_IOC_NR(GTA3XLWIFI_UID_GET_IMAGE)==0x56);
 T(gta3xlwifi_uid_permissions(10001)==0&&gta3xlwifi_uid_permissions_features()==7);
 struct gta3xlwifi_uid_permission_entry e[]={{0,1},{10001,4},{110001,127},{2147483647,1}};
 struct gta3xlwifi_uid_permission_transfer t=tx(1,4,e);
 T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ENOTCONN);
 T(netpolicy_open(NULL,&owner)==0&&gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_UID_FEATURES,NULL)==7&&gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_UID_FEATURES,&t)==-EINVAL);
 T(io(GTA3XLWIFI_UID_SET_IMAGE,NULL)==-EFAULT);
 T(io(GTA3XLWIFI_UID_GET_IMAGE,NULL)==-EFAULT);
 T(io(0x6757,NULL)==-ENOTTY&&gta3xlwifi_netpolicy_held());
 T(netpolicy_image_ioctl(&owner,0x6757,0)==-ENOTTY);
 // All new operations enforce the same root + initial CAP_NET_ADMIN + file/TGID.
 for(unsigned i=0;i<3;i++){
  unsigned cmd=i==0?GTA3XLWIFI_UID_FEATURES:i==1?GTA3XLWIFI_UID_SET_IMAGE:GTA3XLWIFI_UID_GET_IMAGE;void*arg=i?&t:NULL;
  task.euid=1000;T(io(cmd,arg)==-EPERM);task.euid=0;
  task.admin=false;T(io(cmd,arg)==-EPERM);task.admin=true;
  task.tgid=&child_pid;T(io(cmd,arg)==-EPERM);task.tgid=&parent_pid;
  T(netpolicy_ioctl(&other,cmd,(unsigned long)arg)==-EPERM);
 }
 T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0&&revision()==1&&rcu_graces==1);
 for(u32 uid=0;uid<120000;uid++){u32 expected=uid==0?1:uid==10001?4:uid==110001?127:0;assert(gta3xlwifi_uid_permissions(uid)==expected);++comparisons;}
 T(gta3xlwifi_uid_permissions(2147483647)==1&&gta3xlwifi_uid_permissions(0xffffffff)==0);
 T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0&&rcu_graces==1); // idempotent, no replace
 unsigned grace=rcu_graces;u64 rev=revision();
 t.revision=2;alloc_fail=1;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ENOMEM);alloc_fail=0;unchanged(rev,grace);
 from_fail=1;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EFAULT);unchanged(rev,grace);
 from_fail=2;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EFAULT);from_fail=0;unchanged(rev,grace);
 t.version=2;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);t.version=1;
 t.count=65537;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);t.count=4;
 t.entries=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);t.entries=(uintptr_t)e;
 t.count=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);t.count=4;
 e[1].permissions=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);e[1].permissions=128;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);e[1].permissions=4;
 e[1].uid=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);e[1].uid=0xffffffff;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EINVAL);e[1].uid=10001;
 t.revision=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ESTALE);t.revision=3;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ESTALE);
 t.revision=1;e[1].permissions=1;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-ESTALE);e[1].permissions=4;unchanged(rev,grace);
 // GET metadata and coherent full image: stale/capacity/copy failures never write policy.
 struct gta3xlwifi_uid_permission_transfer q=tx(0,0,NULL);
 T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==0&&q.count==4&&q.revision==1&&gta3xlwifi_netpolicy_held());
 struct gta3xlwifi_uid_permission_entry out[8];memset(out,0x5a,sizeof(out));
 q=tx(0,8,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-ESTALE&&out[0].uid==0x5a5a5a5a);
 q=tx(2,8,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-ESTALE);
 q=tx(1,1,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-ENOSPC&&q.count==4&&out[0].uid==0x5a5a5a5a);
 q=tx(1,8,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==0&&q.count==4&&memcmp(e,out,sizeof(e))==0);
 for(int fail=1;fail<=2;fail++){q=tx(1,8,out);to_fail=fail;T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EFAULT);unchanged(rev,grace);}to_fail=0;
 q=tx(1,1,out);to_fail=1;T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EFAULT);to_fail=0;
 T(io(GTA3XLWIFI_NETPOLICY_RELEASE,NULL)==0&&!gta3xlwifi_netpolicy_held());
 t.revision=2;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EBUSY&&revision()==1);
 q=tx(0,0,NULL);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==0&&!gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_UID_FEATURES,NULL)==7&&!gta3xlwifi_netpolicy_held());
 T(io(GTA3XLWIFI_NETPOLICY_HOLD,NULL)==0&&gta3xlwifi_netpolicy_held());
 // Exhaustive bit patterns, core/app/multiuser/literal65534 and privileged controls.
 const u32 uids[]={0,1000,9999,10000,10001,65534,100001,110001,2147483647};
 for(unsigned u=0;u<sizeof(uids)/sizeof(uids[0]);u++)for(u32 mask=0;mask<128;mask++){
  struct gta3xlwifi_uid_permission_entry one={uids[u],mask};
  t=tx(revision()+1,mask?1:0,mask?&one:NULL);assert(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);
  oracle_uid=uids[u];oracle_mask=mask;task.uid=uids[u];
  for(int cap=0;cap<2;cap++)for(int held=0;held<2;held++){
   task.admin=cap;WRITE_ONCE(netpolicy_held,held);
   int expected=oracle(task.uid)==BPF_DISALLOW?-EPERM:held&&task.uid%100000>=10000&&!cap?-EAGAIN:0;
   assert(gta3xlwifi_uid_inet_create_check()==expected);++comparisons;
  }
  task.admin=true;WRITE_ONCE(netpolicy_held,true);
 }
 task.uid=0;
 // Max sized sparse table tests full copy, last-element search and bounded allocation.
 struct gta3xlwifi_uid_permission_entry*many=calloc(65536,sizeof(*many));assert(many);
 for(u32 i=0;i<65536;i++)many[i]=(struct gta3xlwifi_uid_permission_entry){i*2,1};
 t=tx(revision()+1,65536,many);T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);free(many);
 T(gta3xlwifi_uid_permissions(131070)==1&&gta3xlwifi_uid_permissions(131069)==0);
 // Empty replacement is explicit and revisioned, not absent/uninitialized.
 t=tx(revision()+1,0,NULL);T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);
 q=tx(0,0,NULL);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==0&&q.count==0&&q.revision==revision());
 q=tx(0,0,NULL);q.version=0;T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EINVAL);
 q=tx(0,65537,out);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EINVAL);
 q=tx(0,1,NULL);T(io(GTA3XLWIFI_UID_GET_IMAGE,&q)==-EINVAL);
 T(gta3xlwifi_uid_permissions_ioctl(0x6757,0)==-ENOTTY);
 // Overflow never wraps; identical final revision remains idempotent.
 uid_image->revision=UINT64_MAX;t=tx(UINT64_MAX,0,NULL);T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);
 t.revision=0;T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==-EOVERFLOW);uid_image->revision=1;
 struct gta3xlwifi_uid_permission_entry denied={10001,4};t=tx(2,1,&denied);
 T(io(GTA3XLWIFI_UID_SET_IMAGE,&t)==0);
 // Both actual inet tails: init error once, denial once, kern exclusion, success.
 struct fake_proto proto={proto_init};struct fake_sock sk={&proto};
 for(unsigned family=0;family<2;family++){
  int(*tail)(struct fake_sock*,bool)=family?tail1:tail0;
  task.uid=10002;task.admin=false;WRITE_ONCE(netpolicy_held,true);release_count=init_calls=0;init_error=-EIO;
  T(tail(&sk,false)==-EIO&&release_count==1&&init_calls==1);
  init_error=0;release_count=0;T(tail(&sk,false)==-EAGAIN&&release_count==1);
  release_count=0;T(tail(&sk,true)==0&&release_count==0);
  task.uid=10001;WRITE_ONCE(netpolicy_held,false);T(tail(&sk,false)==-EPERM&&release_count==1);
  task.uid=0;release_count=0;T(tail(&sk,false)==0&&release_count==0);
  proto.init=NULL;T(tail(&sk,false)==0&&release_count==0);proto.init=proto_init;
 }
 task.uid=0;task.admin=true;T(netpolicy_flush(&owner,NULL)==0&&gta3xlwifi_netpolicy_held()&&parent_pid.refs==0);
 T(io(GTA3XLWIFI_UID_FEATURES,NULL)==-ENOTCONN);T(netpolicy_release(NULL,&owner)==0);
 vfree(uid_image);uid_image=NULL;T(allocs==frees&&!rcu_depth&&!publication_pending);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
'''
lna_header=S/'include/uapi/linux/netfilter/gta3xlwifi_local_network.h'
if lna_header.exists():
 prefix+='\n#include <linux/netfilter/gta3xlwifi_local_network.h>\nstatic long gta3xlwifi_lna_ioctl(unsigned int c,unsigned long arg){(void)c;(void)arg;assert(!"UID-only regression entered LNA store");return -ENOTTY;}\n'
 if 'gta3xlwifi_lna_packet_features()' in d:
  prefix+='\nstatic u32 gta3xlwifi_lna_packet_features(void){return 0;}\n'
 tests=tests.replace('io(GTA3XLWIFI_UID_FEATURES,NULL)==7','io(GTA3XLWIFI_UID_FEATURES,NULL)==15')
 exported_lna=O/'include/linux/netfilter/gta3xlwifi_local_network.h';exported_lna.parent.mkdir(parents=True,exist_ok=True);exported_lna.write_bytes(lna_header.read_bytes());inputs +=[lna_header,exported_lna]
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
code='\n'.join([prefix,globals,store,functions,oracle,fixture,*tails,tests])
for name in ['gta3xlwifi_uid_permissions.h','gta3xlwifi_netpolicy.h']:
 src=S/'include/uapi/linux/netfilter'/name;dst=O/'include/linux/netfilter'/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes());inputs +=[src,dst]
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',x.stdout);assert match and int(match[1])>=80 and int(match[2])==124608
inputs.append(O/'test.c');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'cases':int(match[1]),'comparisons':int(match[2]),'command':cmd,'inputs_sha256':{str(p):sha(p) for p in inputs},'kernel_runtime_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual C bodies + selected A17 oracle, fatal UBSan')
