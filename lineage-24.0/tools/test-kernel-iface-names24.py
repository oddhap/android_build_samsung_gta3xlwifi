#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual kernel interface-name registry/read ABI with explicit notifier/usercopy fixtures.

Uses pthread locks for actual source's spinlock regions. Kernel build, real
notifier dispatch and Android consumers remain separate validation requirements.
"""
import argparse,hashlib,json,os,re,subprocess,fcntl
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();source=S/'net/netfilter/gta3xlwifi_iface_stats.c';text=source.read_text();start=text.index('/* Names never live');end=text.index('long gta3xlwifi_iface_stats_ioctl(',start);body=text[start:end]
header=S/'include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h';h=O/'include/linux/netfilter/gta3xlwifi_iface_stats.h';h.parent.mkdir(parents=True);h.write_bytes(header.read_bytes())
code=r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
typedef uint32_t u32;typedef uint64_t u64;
#define __user
#define __init
#define __exit
#define EXPORT_SYMBOL_GPL(x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define BUILD_BUG_ON(x) _Static_assert(!(x),"build bug")
#define DEFINE_SPINLOCK(x) pthread_mutex_t x=PTHREAD_MUTEX_INITIALIZER
#define spin_lock_bh(x) assert(!pthread_mutex_lock(x))
#define spin_unlock_bh(x) assert(!pthread_mutex_unlock(x))
#define module_init(x)
#define module_exit(x)
#define IFNAMSIZ 16
#define NETDEV_REGISTER 1
#define NETDEV_CHANGENAME 2
#define NETDEV_UNREGISTER 3
#define NOTIFY_DONE 0
struct net{int unused;};static struct net init_net,other_net;
struct net_device{int ifindex;char name[IFNAMSIZ];struct net*net;};
static struct net*dev_net(struct net_device*d){return d->net;}
static struct net_device*netdev_notifier_info_to_dev(void*d){return d;}
struct notifier_block{int(*notifier_call)(struct notifier_block*,unsigned long,void*);};
static struct net_device seeds[2];static int reg_error;static unsigned registered,unregistered;
static int register_netdevice_notifier(struct notifier_block*n){if(reg_error)return reg_error;++registered;for(unsigned i=0;i<2;i++)if(seeds[i].ifindex)n->notifier_call(n,NETDEV_REGISTER,&seeds[i]);return 0;}
static int unregister_netdevice_notifier(struct notifier_block*n){assert(n);++unregistered;return 0;}
static size_t strlcpy(char*d,const char*s,size_t n){size_t len=strlen(s);if(n){size_t copy=len<n-1?len:n-1;memcpy(d,s,copy);d[copy]=0;}return len;}
static unsigned from_calls,to_calls,from_fault,to_fault,allocs,frees;static bool alloc_fault,producer=true;
static int copy_from_user(void*d,const void*s,size_t n){if(++from_calls==from_fault||!s)return 1;memcpy(d,s,n);return 0;}
static int copy_to_user(void*d,const void*s,size_t n){if(++to_calls==to_fault||!d)return 1;memcpy(d,s,n);return 0;}
static void*vzalloc(size_t n){if(alloc_fault)return NULL;void*p=calloc(1,n);if(p)++allocs;return p;}
static void vfree(void*p){if(p){++frees;free(p);}}
static void sort(void*p,size_t n,size_t size,int(*cmp)(const void*,const void*),void*swap){assert(!swap);qsort(p,n,size,cmp);}
u32 gta3xlwifi_iface_stats_features(void);
'''+body+r'''
u32 gta3xlwifi_iface_stats_features(void){return producer?GTA3XLWIFI_UID_CAP_IFACE_STATS|gta3xlwifi_iface_names_features():0;}
static unsigned cases;
#define C(x) do{if(!(x)){fprintf(stderr,"case=%u line=%u\n",cases,__LINE__);abort();}++cases;}while(0)
static void reset(void){assert(allocs==frees);memset(iface_names_rows,0,sizeof(iface_names_rows));iface_names_count=0;iface_names_lost=iface_names_sequence=0;iface_names_registered=false;memset(seeds,0,sizeof(seeds));reg_error=0;registered=unregistered=0;from_calls=to_calls=from_fault=to_fault=allocs=frees=0;alloc_fault=false;producer=true;}
static struct net_device device(int index,const char*name){struct net_device d={.ifindex=index,.net=&init_net};strlcpy(d.name,name,sizeof(d.name));return d;}
static void event(unsigned kind,struct net_device*d){C(iface_names_notify(&iface_names_notifier,kind,d)==NOTIFY_DONE);}
static long read_names(unsigned count,struct gta3xlwifi_iface_name_entry*rows,struct gta3xlwifi_iface_names_transfer*out){*out=(struct gta3xlwifi_iface_names_transfer){.version=1,.count=count,.entries=(uintptr_t)rows};return iface_names_ioctl((unsigned long)out);}
static void*writer(void*unused){(void)unused;struct net_device d=device(7,"wifi-start");for(unsigned n=0;n<1000;n++){snprintf(d.name,sizeof(d.name),"wifi-%u",n);assert(iface_names_notify(&iface_names_notifier,NETDEV_CHANGENAME,&d)==0);}return NULL;}
int main(void){
 C(sizeof(struct gta3xlwifi_iface_name_entry)==20);C(sizeof(struct gta3xlwifi_iface_names_transfer)==32);C(GTA3XLWIFI_IFACE_NAMES_GET==0xc0206762U);C(GTA3XLWIFI_UID_CAP_IFACE_NAMES==65536U);
 reset();struct gta3xlwifi_iface_names_transfer out;struct gta3xlwifi_iface_name_entry rows[1000];
 C(!gta3xlwifi_iface_names_features());C(read_names(1000,rows,&out)==-EOPNOTSUPP);reg_error=-EIO;C(iface_names_init()==-EIO&&!gta3xlwifi_iface_names_features()&&!registered);reg_error=0;seeds[0]=device(7,"wlan0");seeds[1]=device(1,"lo");C(!iface_names_init()&&registered==1);C(gta3xlwifi_iface_names_features()==65536U);C(!read_names(0,NULL,&out)&&out.count==2&&out.update_sequence==2&&!out.lost_updates);C(!read_names(1000,rows,&out)&&out.count==2&&rows[0].ifindex==1&&!strcmp(rows[0].name,"lo")&&rows[1].ifindex==7&&!strcmp(rows[1].name,"wlan0"));
 struct net_device d=device(7,"v4-wlan0");event(NETDEV_CHANGENAME,&d);C(!read_names(1000,rows,&out)&&out.count==2&&!strcmp(rows[1].name,"v4-wlan0"));event(NETDEV_UNREGISTER,&d);C(!read_names(1000,rows,&out)&&out.count==2&&!strcmp(rows[1].name,"v4-wlan0"));d=device(7,"x");event(NETDEV_REGISTER,&d);C(!read_names(1000,rows,&out)&&out.count==2&&!strcmp(rows[1].name,"x"));for(unsigned i=2;i<16;i++)C(rows[1].name[i]==0);
 d=device(8,"foreign");d.net=&other_net;event(NETDEV_REGISTER,&d);C(!read_names(1000,rows,&out)&&out.count==2&&!out.lost_updates);
 C(iface_names_ioctl(0)==-EFAULT);out=(struct gta3xlwifi_iface_names_transfer){.version=2};C(iface_names_ioctl((unsigned long)&out)==-EINVAL);out=(struct gta3xlwifi_iface_names_transfer){.version=1,.count=1001};C(iface_names_ioctl((unsigned long)&out)==-EINVAL);out=(struct gta3xlwifi_iface_names_transfer){.version=1,.count=1};C(iface_names_ioctl((unsigned long)&out)==-EINVAL);out=(struct gta3xlwifi_iface_names_transfer){.version=1,.entries=(uintptr_t)rows};C(iface_names_ioctl((unsigned long)&out)==-EINVAL);
 C(read_names(1,rows,&out)==-ENOSPC&&allocs==frees);alloc_fault=true;C(read_names(1000,rows,&out)==-ENOMEM);alloc_fault=false;from_fault=from_calls+1;C(read_names(1000,rows,&out)==-EFAULT);from_fault=0;for(unsigned i=1;i<=2;i++){to_fault=to_calls+i;C(read_names(1000,rows,&out)==-EFAULT&&allocs==frees);to_fault=0;}
 d=device(0,"bad");event(NETDEV_REGISTER,&d);d=device(9,"");event(NETDEV_REGISTER,&d);d=device(9,"bad");memset(d.name,'x',16);event(NETDEV_REGISTER,&d);C(!read_names(1000,rows,&out)&&out.lost_updates==3&&out.count==2);
 producer=false;C(read_names(1000,rows,&out)==-EOPNOTSUPP);producer=true;iface_names_exit();C(!gta3xlwifi_iface_names_features()&&unregistered==1&&read_names(1000,rows,&out)==-EOPNOTSUPP);
 reset();C(!iface_names_init());for(unsigned i=1000;i>0;i--){d=device(i,"net");event(NETDEV_REGISTER,&d);}C(!read_names(1000,rows,&out)&&out.count==1000&&!out.lost_updates);for(unsigned i=0;i<1000;i++)C(rows[i].ifindex==i+1);d=device(1001,"overflow");event(NETDEV_REGISTER,&d);C(!read_names(1000,rows,&out)&&out.count==1000&&out.lost_updates==1);iface_names_lost=UINT64_MAX;event(NETDEV_REGISTER,&d);C(!read_names(1000,rows,&out)&&out.lost_updates==UINT64_MAX);d=device(1,"reused");event(NETDEV_REGISTER,&d);C(!read_names(1000,rows,&out)&&!strcmp(rows[0].name,"reused")&&out.lost_updates==UINT64_MAX);
 reset();seeds[0]=device(1,"lo");seeds[1]=device(7,"wifi-start");C(!iface_names_init());pthread_t thread;C(!pthread_create(&thread,NULL,writer,NULL));for(unsigned n=0;n<1000;n++){C(!read_names(1000,rows,&out)&&out.count==2&&!out.lost_updates&&rows[0].ifindex==1&&rows[1].ifindex==7);C(!strncmp(rows[1].name,"wifi-",5)&&memchr(rows[1].name,0,16));}C(!pthread_join(thread,NULL));C(!read_names(1000,rows,&out)&&out.update_sequence==1002&&!strcmp(rows[1].name,"wifi-999")&&allocs==frees);
 printf("passed_cases=%u concurrent_snapshots=1000\n",cases);return 0;
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(O/'include'),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.fullmatch(r'passed_cases=(\d+) concurrent_snapshots=1000\n',x.stdout);assert m
paths=[Path(__file__),O/'test.c',*[q for q in S.rglob('*') if q.is_file()]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'concurrent_snapshots':1000,'registry_capacity':1000,'real_source_body_and_UAPI':True,'notifier_replay_rename_unregister_reuse_namespace_loss_and_copy_faults':True,'inputs_sha256':{str(q):sha(q) for q in paths},'command':cmd,'actual_kernel_builded':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
