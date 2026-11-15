
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
/* Names never live in userspace caches or depend on a daemon's lifetime.
 * Registration replays existing devices under RTNL. Retain removed ifindices;
 * an actual later register/rename for the same index replaces its current name.
 */
static DEFINE_SPINLOCK(iface_names_lock);
static struct gta3xlwifi_iface_name_entry iface_names_rows[GTA3XLWIFI_IFACE_STATS_MAX];
static u32 iface_names_count;
static u64 iface_names_lost,iface_names_sequence;
static bool iface_names_registered;
u32 gta3xlwifi_iface_names_features(void)
{
    return READ_ONCE(iface_names_registered)?GTA3XLWIFI_UID_CAP_IFACE_NAMES:0;
}
EXPORT_SYMBOL_GPL(gta3xlwifi_iface_names_features);
static int iface_names_notify(struct notifier_block *block,unsigned long event,void *data)
{
    struct net_device *device=netdev_notifier_info_to_dev(data);
    struct gta3xlwifi_iface_name_entry *row=NULL;
    u32 i;
    (void)block;
    if((event!=NETDEV_REGISTER&&event!=NETDEV_CHANGENAME)||
       dev_net(device)!=&init_net)return NOTIFY_DONE;
    spin_lock_bh(&iface_names_lock);
    if(device->ifindex<=0||!device->name[0]||
       strnlen(device->name,IFNAMSIZ)==IFNAMSIZ){
        if(iface_names_lost!=~(u64)0)++iface_names_lost;
        ++iface_names_sequence;
        spin_unlock_bh(&iface_names_lock);return NOTIFY_DONE;
    }
    for(i=0;i<iface_names_count;++i)
        if(iface_names_rows[i].ifindex==(u32)device->ifindex){row=&iface_names_rows[i];break;}
    if(!row){
        if(iface_names_count==GTA3XLWIFI_IFACE_STATS_MAX){
            if(iface_names_lost!=~(u64)0)++iface_names_lost;
            ++iface_names_sequence;
            spin_unlock_bh(&iface_names_lock);return NOTIFY_DONE;
        }
        row=&iface_names_rows[iface_names_count++];row->ifindex=device->ifindex;
    }
    memset(row->name,0,sizeof(row->name));
    strlcpy(row->name,device->name,sizeof(row->name));
    ++iface_names_sequence;
    spin_unlock_bh(&iface_names_lock);return NOTIFY_DONE;
}
static struct notifier_block iface_names_notifier={.notifier_call=iface_names_notify};
static int __init iface_names_init(void)
{
    int result;
    BUILD_BUG_ON(sizeof(iface_names_rows[0].name)!=IFNAMSIZ);
    result=register_netdevice_notifier(&iface_names_notifier);
    if(!result)WRITE_ONCE(iface_names_registered,true);
    return result;
}
static void __exit iface_names_exit(void)
{
    WRITE_ONCE(iface_names_registered,false);
    unregister_netdevice_notifier(&iface_names_notifier);
}
module_init(iface_names_init);
module_exit(iface_names_exit);
static int iface_name_compare(const void *left,const void *right)
{
    const struct gta3xlwifi_iface_name_entry *a=left,*b=right;
    return a->ifindex<b->ifindex?-1:a->ifindex>b->ifindex?1:0;
}
static long iface_names_ioctl(unsigned long arg)
{
    struct gta3xlwifi_iface_names_transfer request,answer;
    struct gta3xlwifi_iface_name_entry *rows=NULL;
    int result=0;
    if(!arg)return -EFAULT;
    if(!(gta3xlwifi_iface_stats_features()&GTA3XLWIFI_UID_CAP_IFACE_NAMES))return -EOPNOTSUPP;
    if(copy_from_user(&request,(void __user *)arg,sizeof(request)))return -EFAULT;
    if(request.version!=GTA3XLWIFI_IFACE_NAMES_VERSION||
       request.count>GTA3XLWIFI_IFACE_STATS_MAX||
       (!!request.count!=!!request.entries)||request.lost_updates||request.update_sequence)return -EINVAL;
    if(request.count){rows=vzalloc(request.count*sizeof(*rows));if(!rows)return -ENOMEM;}
    answer=request;
    spin_lock_bh(&iface_names_lock);
    answer.count=iface_names_count;answer.lost_updates=iface_names_lost;
    answer.update_sequence=iface_names_sequence;
    if(request.count&&request.count<answer.count)result=-ENOSPC;
    else if(request.count)memcpy(rows,iface_names_rows,answer.count*sizeof(*rows));
    spin_unlock_bh(&iface_names_lock);
    if(!result&&request.count){
        sort(rows,answer.count,sizeof(*rows),iface_name_compare,NULL);
        if(copy_to_user((void __user *)(unsigned long)request.entries,rows,
                        answer.count*sizeof(*rows)))result=-EFAULT;
    }
    if(!result&&copy_to_user((void __user *)arg,&answer,sizeof(answer)))result=-EFAULT;
    vfree(rows);return result;
}

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
