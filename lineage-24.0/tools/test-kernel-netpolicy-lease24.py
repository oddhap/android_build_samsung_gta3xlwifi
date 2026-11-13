#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test real packet-barrier lease code with synthetic file/PID/net-grace effects.

Uses actual C bodies, real pthread mutex/contended close, and atomic memory order.
PID refs, credentials, registration, grace periods and packets remain fixtures;
no host/device kernel, rule, network, credential or descriptor is changed.
"""
import argparse,hashlib,importlib.util,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
text=(S/'net/netfilter/gta3xlwifi_netpolicy.c').read_text();header=S/'include/uapi/linux/netfilter/gta3xlwifi_netpolicy.h'
spec=importlib.util.spec_from_file_location('extract',Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
names=['netpolicy_privileged','netpolicy_open','netpolicy_drop_lease','netpolicy_flush','netpolicy_release','netpolicy_ioctl','netpolicy_match','netpolicy_check']
globals=text[text.index('static DEFINE_MUTEX('):text.index('static bool netpolicy_privileged(')]
metadata=text[text.index('static const struct file_operations'):text.index('static int __init gta3xlwifi_netpolicy_init(')]
prefix=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <linux/netfilter/gta3xlwifi_netpolicy.h>
#define CONFIG_COMPAT 1
#define __read_mostly
#define __init
#define THIS_MODULE NULL
#define MISC_DYNAMIC_MINOR 255
#define CAP_NET_ADMIN 12
#define GLOBAL_ROOT_UID 0
#define NFPROTO_UNSPEC 0
#define NF_INET_LOCAL_IN 1
#define NF_INET_FORWARD 2
#define NF_INET_LOCAL_OUT 3
struct inode{int unused;};struct file{int identity;};typedef void* fl_owner_t;
struct pid{unsigned identity;int refs;};
struct task_struct{unsigned uid;bool admin;struct pid* tgid;};
static __thread struct task_struct* current;
static int init_user_ns;
static unsigned current_euid(void){return current->uid;}
static bool uid_eq(unsigned a,unsigned b){return a==b;}
static bool ns_capable(const void* ns,int capability){assert(ns==&init_user_ns&&capability==CAP_NET_ADMIN);return current->admin;}
static struct pid* task_tgid(struct task_struct* task){return task->tgid;}
static struct pid* get_pid(struct pid* p){assert(p);++p->refs;return p;}
static void put_pid(struct pid* p){assert(p&&p->refs>0);--p->refs;}
#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER
static void checked_mutex_lock(pthread_mutex_t* lock);
#define mutex_lock(n) checked_mutex_lock(n)
#define mutex_unlock(n) assert(pthread_mutex_unlock(n)==0)
#define WRITE_ONCE(p,v) __atomic_store_n(&(p),(v),__ATOMIC_RELAXED)
#define READ_ONCE(p) __atomic_load_n(&(p),__ATOMIC_RELAXED)
#define smp_store_release(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
struct sk_buff{int unused;};struct xt_action_param{int family;};
struct xt_mtchk_param{const void* matchinfo;};
struct file_operations{void*owner;int(*open)(struct inode*,struct file*);int(*flush)(struct file*,fl_owner_t);int(*release)(struct inode*,struct file*);long(*unlocked_ioctl)(struct file*,unsigned int,unsigned long);long(*compat_ioctl)(struct file*,unsigned int,unsigned long);};
struct miscdevice{int minor;const char*name;const struct file_operations*fops;unsigned mode;};
struct xt_match{const char*name;unsigned revision,family,hooks;bool(*match)(const struct sk_buff*,struct xt_action_param*);int(*checkentry)(const struct xt_mtchk_param*);unsigned matchsize;void*me;};
static unsigned syncs;
static bool pause_grace,reached_grace,allow_grace,waiter_blocked;
static __thread bool is_closer;
static pthread_mutex_t coordination=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
'''
sync=r'''
static void checked_mutex_lock(pthread_mutex_t* lock){
 if(is_closer){assert(pthread_mutex_trylock(lock)==EBUSY);pthread_mutex_lock(&coordination);waiter_blocked=true;pthread_cond_broadcast(&condition);pthread_mutex_unlock(&coordination);}
 assert(pthread_mutex_lock(lock)==0);
}
static void synchronize_net(void){
 assert(READ_ONCE(netpolicy_held));++syncs;
 assert(pthread_mutex_lock(&coordination)==0);
 if(pause_grace){reached_grace=true;pthread_cond_broadcast(&condition);while(!allow_grace)pthread_cond_wait(&condition,&coordination);}
 pthread_mutex_unlock(&coordination);
}
'''
registration=r'''
static int register_error,misc_error;
static unsigned registers,unregisters,misc_calls;
static int xt_register_match(struct xt_match* m){assert(m==&netpolicy_match_reg);++registers;return register_error;}
static void xt_unregister_match(struct xt_match* m){assert(m==&netpolicy_match_reg);++unregisters;}
static int misc_register(struct miscdevice* m){assert(m==&netpolicy_device);++misc_calls;return misc_error;}
'''
tests=r'''
static struct pid parent_pid={42,0},child_pid={43,0};
static struct task_struct parent={0,true,&parent_pid},child={0,true,&child_pid};
static struct file owner={1},foreign={2};
static long open_result;
static void* releasing(void* arg){(void)arg;current=&parent;open_result=netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0);return NULL;}
static void* closing(void* arg){(void)arg;current=&parent;is_closer=true;assert(netpolicy_flush(&owner,NULL)==0);return NULL;}
int main(void){unsigned checks=0;current=&parent;
#define C(x) do{assert(x);++checks;}while(0)
 C(GTA3XLWIFI_NETPOLICY_ABI==0x6750&&GTA3XLWIFI_NETPOLICY_HOLD==0x6751&&GTA3XLWIFI_NETPOLICY_RELEASE==0x6752&&GTA3XLWIFI_NETPOLICY_STATE==0x6753);
 C(sizeof(struct gta3xlwifi_netpolicy_match)==4);
 C(netpolicy_match(NULL,NULL));
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_STATE,0)==-ENOTCONN);
 parent.uid=1000;C(netpolicy_open(NULL,&owner)==-EPERM);parent.uid=0;parent.admin=false;C(netpolicy_open(NULL,&owner)==-EPERM);parent.admin=true;parent.tgid=NULL;C(netpolicy_open(NULL,&owner)==-EPERM);parent.tgid=&parent_pid;
 C(netpolicy_open(NULL,&owner)==0&&parent_pid.refs==1&&syncs==1);
 C(netpolicy_open(NULL,&foreign)==-EBUSY&&parent_pid.refs==1);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_ABI,0)==1);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_STATE,0)==1);
 C(netpolicy_ioctl(&owner,0x6754,0)==-ENOTTY);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,1)==-EINVAL&&netpolicy_match(NULL,NULL));
 C(netpolicy_ioctl(&foreign,GTA3XLWIFI_NETPOLICY_RELEASE,0)==-EPERM);
 current=&child;C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==-EPERM);current=&parent;
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0&&!netpolicy_match(NULL,NULL)&&syncs==2);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0&&syncs==2);
 current=&child;C(netpolicy_flush(&owner,NULL)==0&&!netpolicy_match(NULL,NULL)&&parent_pid.refs==1);current=&parent;
 parent.admin=false;C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==-EPERM);parent.admin=true;
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0&&netpolicy_match(NULL,NULL)&&syncs==3);
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0&&!netpolicy_match(NULL,NULL));
 parent.uid=1000;parent.admin=false;C(netpolicy_flush(&owner,NULL)==0&&netpolicy_match(NULL,NULL)&&parent_pid.refs==0);parent.uid=0;parent.admin=true;
 C(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_STATE,0)==-ENOTCONN);
 C(netpolicy_open(NULL,&foreign)==0&&parent_pid.refs==1);
 C(netpolicy_release(NULL,&owner)==0&&netpolicy_owner_file==&foreign&&parent_pid.refs==1);
 C(netpolicy_ioctl(&foreign,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0&&!netpolicy_match(NULL,NULL));
 current=&child;C(netpolicy_release(NULL,&foreign)==0&&netpolicy_match(NULL,NULL)&&parent_pid.refs==0);current=&parent;
 struct gta3xlwifi_netpolicy_match info={{0}};struct xt_mtchk_param param={&info};C(netpolicy_check(&param)==0);
 for(unsigned i=0;i<4;i++){info.reserved[i]=1;C(netpolicy_check(&param)==-EINVAL);info.reserved[i]=0;}
 C(netpolicy_fops.flush==netpolicy_flush&&netpolicy_fops.compat_ioctl==netpolicy_ioctl);
 C(netpolicy_device.mode==0400);
 C(netpolicy_match_reg.family==NFPROTO_UNSPEC&&netpolicy_match_reg.hooks==((1<<NF_INET_LOCAL_IN)|(1<<NF_INET_FORWARD)|(1<<NF_INET_LOCAL_OUT))&&netpolicy_match_reg.matchsize==4);
 register_error=-ENOMEM;C(gta3xlwifi_netpolicy_init()==-ENOMEM&&registers==1&&misc_calls==0&&unregisters==0);
 register_error=0;misc_error=-EBUSY;C(gta3xlwifi_netpolicy_init()==-EBUSY&&registers==2&&misc_calls==1&&unregisters==1);
 misc_error=0;C(gta3xlwifi_netpolicy_init()==0&&registers==3&&misc_calls==2&&unregisters==1);
 C(netpolicy_open(NULL,&owner)==0);pause_grace=true;reached_grace=false;allow_grace=false;
 pthread_t a,b;C(pthread_create(&a,NULL,releasing,NULL)==0);
 pthread_mutex_lock(&coordination);while(!reached_grace)pthread_cond_wait(&condition,&coordination);C(netpolicy_match(NULL,NULL));pthread_mutex_unlock(&coordination);
 C(pthread_create(&b,NULL,closing,NULL)==0);
 pthread_mutex_lock(&coordination);while(!waiter_blocked)pthread_cond_wait(&condition,&coordination);allow_grace=true;pthread_cond_broadcast(&condition);pthread_mutex_unlock(&coordination);
 C(pthread_join(a,NULL)==0&&pthread_join(b,NULL)==0&&open_result==0&&netpolicy_match(NULL,NULL)&&parent_pid.refs==0);
 C(netpolicy_owner_file==NULL&&netpolicy_owner_pid==NULL);
 printf("passed_cases=%u\n",checks);
}
'''
# Backward-compatible extension: this regression deliberately exercises only
# the original four commands. New image dispatch is tested independently.
image_header=S/'include/uapi/linux/netfilter/gta3xlwifi_uid_permissions.h'
if image_header.exists():
 prefix += '\n#include <linux/netfilter/gta3xlwifi_uid_permissions.h>\n#define EXPORT_SYMBOL_GPL(x)\nstatic long netpolicy_image_ioctl(struct file*f,unsigned int c,unsigned long a){(void)f;(void)c;(void)a;assert(!"legacy test entered image dispatch");return -ENOTTY;}\n'
 tests=tests.replace('netpolicy_ioctl(&owner,0x6754,0)', 'netpolicy_ioctl(&owner,0x6757,0)')
 exported_image=O/'include/linux/netfilter/gta3xlwifi_uid_permissions.h';exported_image.parent.mkdir(parents=True,exist_ok=True);exported_image.write_bytes(image_header.read_bytes())
lna_header=S/'include/uapi/linux/netfilter/gta3xlwifi_local_network.h'
if lna_header.exists():
 prefix+='\n#include <linux/netfilter/gta3xlwifi_local_network.h>\n'
 exported_lna=O/'include/linux/netfilter/gta3xlwifi_local_network.h';exported_lna.parent.mkdir(parents=True,exist_ok=True);exported_lna.write_bytes(lna_header.read_bytes())
metrics_header=S/'include/uapi/linux/netfilter/gta3xlwifi_loopback.h'
if metrics_header.exists():
 prefix+='\n#include <linux/netfilter/gta3xlwifi_loopback.h>\n'
 exported_metrics=O/'include/linux/netfilter/gta3xlwifi_loopback.h';exported_metrics.parent.mkdir(parents=True,exist_ok=True);exported_metrics.write_bytes(metrics_header.read_bytes())
iface_header=S/'include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h'
if iface_header.exists():
 prefix+='\n#include <linux/netfilter/gta3xlwifi_iface_stats.h>\n'
 exported_iface=O/'include/linux/netfilter/gta3xlwifi_iface_stats.h';exported_iface.parent.mkdir(parents=True,exist_ok=True);exported_iface.write_bytes(iface_header.read_bytes())
code=prefix+globals+sync+'\n'.join(m.extract(text,n) for n in names)+metadata+registration+m.extract(text,'gta3xlwifi_netpolicy_init')+tests
# Export only this UAPI header; use the host's installed Linux ABI dependencies.
# Adding the raw kernel UAPI tree would accidentally include unexported headers.
exported=O/'include/linux/netfilter/gta3xlwifi_netpolicy.h';exported.parent.mkdir(parents=True,exist_ok=True);exported.write_bytes(header.read_bytes())
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=30);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
assert r.stdout=='passed_cases=44\n',r.stdout
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__).resolve(),Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py').resolve(),O/'test.c',S/'net/netfilter/gta3xlwifi_netpolicy.c',header,exported]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':44,'stderr':r.stderr,'command':cmd,'inputs_sha256':{str(p):sha(p) for p in paths},'packet_or_kernel_runtime_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: 44 actual lease/match/registration/grace-order cases with real mutex contention, fatal UBSan')
