
#include "Gta3xlwifiNetpolicyLease.h"
#include <linux/netfilter/gta3xlwifi_netpolicy.h>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <string>
#include <thread>
#include <vector>
#include <cstdio>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>
using android::net::gta3xlwifi::NetpolicyLease;
unsigned cases=0;
#define C(x) do {++cases;assert(x);}while(0)
const std::string node="/dev/gta3xlwifi_netpolicy",identity="/sys/devices/virtual/misc/gta3xlwifi_netpolicy/dev";
struct Entry {std::string path;size_t offset=0;};std::map<int,Entry> files;
int nextfd=10000,opens=0,closes=0,openError=0,statError=0,fsError=0,readError=0;
int openEintr=0,readEintr=0,ioctlEintr=0,abi=1,ioctlError=0,stateOverride=-1,ack=0;
unsigned long errorCommand=0;bool held=true,wrongType=false,wrongSysfs=false,commitError=false,closeEintr=false;
uid_t nodeUid=0,sysfsUid=0;gid_t nodeGid=0;mode_t mode=0400;unsigned minorNumber=64;
std::string text="10:64\n";size_t chunk=100;
extern "C" int __real_close(int);
extern "C" int __real_fstat(int,struct stat*);
extern "C" int __wrap_open(const char* path,int flags,...){
 assert(flags&O_NOFOLLOW);assert(flags&O_CLOEXEC);assert((flags&O_ACCMODE)==O_RDONLY);
 assert(path==node||path==identity);
 if(openEintr){--openEintr;errno=EINTR;return -1;}
 if(openError){errno=openError;return -1;}
 if(path==node){assert(opens==0);++opens;held=true;}
 int fd=nextfd++;files.emplace(fd,Entry{path,0});return fd;
}
extern "C" int __wrap_close(int fd){
 auto i=files.find(fd);if(i==files.end())return __real_close(fd);
 bool isnode=i->second.path==node;if(isnode){++closes;--opens;held=true;}files.erase(i);
 if(isnode&&closeEintr){errno=EINTR;return -1;}return 0;
}
extern "C" int __wrap_fstat(int fd,struct stat* out){
 auto i=files.find(fd);if(i==files.end())return __real_fstat(fd,out);
 if(statError){errno=statError;return -1;}bool n=i->second.path==node;
 memset(out,0,sizeof(*out));out->st_mode=(n?S_IFCHR:S_IFREG)|(n?mode:0444);
 if(wrongType)out->st_mode=S_IFIFO;
 out->st_uid=n?nodeUid:sysfsUid;out->st_gid=n?nodeGid:0;out->st_rdev=makedev(10,minorNumber);return 0;
}
extern "C" int __wrap_fstatfs(int fd,struct statfs* out){
 assert(files.count(fd)&&files.at(fd).path==identity);if(fsError){errno=fsError;return -1;}
 memset(out,0,sizeof(*out));out->f_type=wrongSysfs?0x1234:0x62656572;return 0;
}
extern "C" ssize_t __wrap_read(int fd,void* buffer,size_t size){
 assert(files.count(fd)&&files.at(fd).path==identity);
 if(readEintr){--readEintr;errno=EINTR;return -1;}if(readError){errno=readError;return -1;}
 auto& e=files.at(fd);size_t n=std::min(std::min(size,chunk),text.size()-e.offset);
 memcpy(buffer,text.data()+e.offset,n);e.offset+=n;return n;
}
extern "C" ssize_t __wrap___read_chk(int fd,void* b,size_t n,size_t capacity){assert(n<=capacity);return __wrap_read(fd,b,n);}

#include <linux/netfilter/gta3xlwifi_uid_permissions.h>
#include <climits>
using Wire=gta3xlwifi_uid_permission_entry;
std::vector<Wire> kernelImage;
uint64_t kernelRevision=0;
int features=7,imageIoctls=0,getCalls=0,setCalls=0,getFaultAt=0,getFault=0;
int getErrorAt=0,getError=0,setError=0,setAck=0,setEintrAfterCommit=0;
bool commitThenError=false,releaseAfterSet=false;
static bool equalWire(const std::vector<Wire>&a,const std::vector<Wire>&b){return a.size()==b.size()&&(a.empty()||!memcmp(a.data(),b.data(),a.size()*sizeof(a[0])));}
extern "C" int uid_ioctl(int fd,unsigned long cmd,...){
 assert(files.count(fd)&&files.at(fd).path==node);
 va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);
 if(ioctlEintr){--ioctlEintr;errno=EINTR;return -1;}
 if(ioctlError&&cmd==errorCommand){errno=ioctlError;return -1;}
 if(cmd>=0x6750&&cmd<=0x6753){
  assert(arg==0);
  if(cmd==GTA3XLWIFI_NETPOLICY_ABI)return abi;
  if(cmd==GTA3XLWIFI_NETPOLICY_STATE)return stateOverride>=0?stateOverride:int(held);
  held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;
 }
 ++imageIoctls;
 if(cmd==GTA3XLWIFI_UID_FEATURES){assert(!arg);return features;}
 assert(arg);auto*t=reinterpret_cast<gta3xlwifi_uid_permission_transfer*>(arg);
 assert(t->version==1&&t->count<=65536&&bool(t->count)==bool(t->entries));
 auto*buffer=reinterpret_cast<Wire*>(static_cast<uintptr_t>(t->entries));
 if(cmd==GTA3XLWIFI_UID_GET_IMAGE){
  ++getCalls;if(getCalls==getErrorAt){errno=getError;return -1;}
  if(t->count){
   if(t->revision!=kernelRevision||!t->revision){errno=ESTALE;return -1;}
   assert(t->count>=kernelImage.size());if(!kernelImage.empty())memcpy(buffer,kernelImage.data(),kernelImage.size()*sizeof(Wire));
  }
  t->count=kernelImage.size();t->revision=kernelRevision;
  if(getCalls==getFaultAt){
   switch(getFault){
    case 1:t->version=2;break;
    case 2:t->count=65537;break;
    case 3:t->entries=17;break;
    case 4:++t->revision;break;
    case 5:assert(buffer&&t->count);buffer[0].permissions=128;break;
    case 6:assert(buffer&&t->count);buffer[0].uid=UINT32_MAX;break;
    case 7:assert(buffer&&t->count>1);buffer[1].uid=buffer[0].uid;break;
    case 8:assert(buffer&&t->count);buffer[0].permissions=1;break;
    case 9:assert(buffer&&t->count);buffer[0].permissions=0;break;
    case 10:t->revision=0;break;
    default:assert(false);
   }
  }
  return 0;
 }
 assert(cmd==GTA3XLWIFI_UID_SET_IMAGE&&held);++setCalls;
 if(setError&&!commitThenError){errno=setError;return -1;}
 std::vector<Wire> next;if(t->count)next.assign(buffer,buffer+t->count);
 for(size_t i=0;i<next.size();i++)assert(next[i].uid<=INT_MAX&&next[i].permissions&&next[i].permissions<128&&(!i||next[i-1].uid<next[i].uid));
 if(t->revision==kernelRevision){assert(equalWire(next,kernelImage));}
 else{assert(t->revision==kernelRevision+1);kernelImage=next;kernelRevision=t->revision;}
 if(setEintrAfterCommit){--setEintrAfterCommit;errno=EINTR;return -1;}
 if(releaseAfterSet)held=false;
 if(setError){errno=setError;return -1;}return setAck;
}
void reset(){assert(files.empty()&&opens==0);closes=0;openError=statError=fsError=readError=0;
 openEintr=readEintr=ioctlEintr=0;abi=1;ioctlError=0;errorCommand=0;stateOverride=-1;ack=0;
 held=true;wrongType=wrongSysfs=commitError=closeEintr=false;nodeUid=sysfsUid=nodeGid=0;mode=0400;minorNumber=64;text="10:64\n";chunk=100;}

using EntryValue=NetpolicyLease::PermissionEntry;
using ImageValue=NetpolicyLease::PermissionImage;
void resetImage(){reset();kernelImage.clear();kernelRevision=0;features=7;imageIoctls=getCalls=setCalls=getFaultAt=getFault=getErrorAt=getError=setError=setAck=setEintrAfterCommit=0;commitThenError=releaseAfterSet=false;}
void seed(){kernelRevision=9;kernelImage={{10001,4},{110001,127}};}
ImageValue sentinel(){return {777,{{555,1}}};}
bool untouched(const ImageValue&v){return v.revision==777&&v.entries==std::vector<EntryValue>{{555,1}};}
const std::vector<EntryValue> wanted={{10001,4},{110001,127}};

#include <linux/netfilter/gta3xlwifi_local_network.h>
using LWire=gta3xlwifi_lna_entry;using LEntry=NetpolicyLease::LocalNetworkEntry;using LImage=NetpolicyLease::LocalNetworkImage;
std::vector<LWire> netImage,hostImage;uint64_t lnaRevision=0;
unsigned lnaIoctls=0,lnaGets=0,lnaSets=0;unsigned lnaFaultAt=0,lnaFault=0,lnaErrorAt=0;int lnaError=0,lnaSetError=0,lnaAck=0,lnaEintr=0;
bool lnaCommitError=false,lnaReleaseAfterSet=false;
bool equalLWire(const std::vector<LWire>&a,const std::vector<LWire>&b){return a.size()==b.size()&&(a.empty()||!memcmp(a.data(),b.data(),a.size()*sizeof(LWire)));}
extern "C" int image_ioctl(int fd,unsigned long cmd,...){
 va_list args;va_start(args,cmd);unsigned long arg=va_arg(args,unsigned long);va_end(args);
 if(cmd!=GTA3XLWIFI_LNA_SET_IMAGE&&cmd!=GTA3XLWIFI_LNA_GET_IMAGE)return uid_ioctl(fd,cmd,arg);
 assert(files.count(fd)&&files.at(fd).path==node);++lnaIoctls;
 if(ioctlEintr){--ioctlEintr;errno=EINTR;return -1;}
 if(ioctlError&&cmd==errorCommand){errno=ioctlError;return -1;}
 assert(arg);auto*t=reinterpret_cast<gta3xlwifi_lna_transfer*>(arg);assert(t->version==1&&!t->reserved&&t->network_count<=1000&&t->host_count<=1000&&bool(t->network_count)==bool(t->network_entries)&&bool(t->host_count)==bool(t->host_entries));
 auto*n=reinterpret_cast<LWire*>(static_cast<uintptr_t>(t->network_entries));auto*h=reinterpret_cast<LWire*>(static_cast<uintptr_t>(t->host_entries));
 if(cmd==GTA3XLWIFI_LNA_GET_IMAGE){
  ++lnaGets;if(lnaGets==lnaErrorAt){errno=lnaError;return -1;}
  if(t->network_count||t->host_count){
   if(t->revision!=lnaRevision||!t->revision){errno=ESTALE;return -1;}
   assert(t->network_count>=netImage.size()&&t->host_count>=hostImage.size());if(!netImage.empty())memcpy(n,netImage.data(),netImage.size()*sizeof(LWire));if(!hostImage.empty())memcpy(h,hostImage.data(),hostImage.size()*sizeof(LWire));
  }
  t->revision=lnaRevision;t->network_count=netImage.size();t->host_count=hostImage.size();
  if(lnaGets==lnaFaultAt){switch(lnaFault){
   case 1:t->version=2;break;case 2:t->reserved=1;break;case 3:t->network_count=1001;break;case 4:t->host_count=1001;break;
   case 5:t->network_entries=17;break;case 6:t->host_entries=18;break;case 7:++t->revision;break;case 8:t->revision=0;break;
   case 9:n[0].prefix_bits=193;break;case 10:h[0].allowed=2;break;case 11:n[0].reserved[2]=1;break;case 12:h[0].reserved[0]=1;break;
   case 13:n[0].key[23]=1;break;case 14:n[1]=n[0];break;case 15:std::swap(h[0],h[1]);break;case 16:n[0].allowed=!n[0].allowed;break;case 17:h[0].allowed=!h[0].allowed;break;
   case 18:--t->network_count;break;case 19:--t->host_count;break;default:assert(false);
  }}return 0;
 }
 assert(held);++lnaSets;if(lnaSetError&&!lnaCommitError){errno=lnaSetError;return -1;}
 std::vector<LWire> nextN,nextH;if(t->network_count)nextN.assign(n,n+t->network_count);if(t->host_count)nextH.assign(h,h+t->host_count);
 if(t->revision==lnaRevision){assert(equalLWire(nextN,netImage)&&equalLWire(nextH,hostImage));}
 else{assert(t->revision==lnaRevision+1);netImage=nextN;hostImage=nextH;lnaRevision=t->revision;}
 if(lnaEintr){--lnaEintr;errno=EINTR;return -1;}if(lnaReleaseAfterSet)held=false;if(lnaSetError){errno=lnaSetError;return -1;}return lnaAck;
}
LEntry entry(uint32_t bits,uint8_t first,bool allow){LEntry e={bits,{},allow};e.key[0]=first;return e;}
const std::vector<LEntry> network={entry(0,0,false),entry(64,1,true),entry(192,2,false)},host={entry(64,3,true),entry(192,4,true)};
std::vector<LWire> encode(const std::vector<LEntry>&v){std::vector<LWire>w(v.size());for(size_t i=0;i<v.size();i++){w[i].prefix_bits=v[i].prefixBits;memcpy(w[i].key,v[i].key.data(),24);w[i].allowed=v[i].allowed;}return w;}
void resetLna(){resetImage();features=127;netImage.clear();hostImage.clear();lnaRevision=0;lnaIoctls=lnaGets=lnaSets=lnaFaultAt=lnaFault=lnaErrorAt=0;lnaError=lnaSetError=lnaAck=lnaEintr=0;lnaCommitError=lnaReleaseAfterSet=false;}
void seedLna(){lnaRevision=9;netImage=encode(network);hostImage=encode(host);}
LImage sentinelLna(){return {777,{entry(192,77,true)},{entry(64,88,false)}};}
bool untouchedLna(const LImage&v){auto expected=sentinelLna();return v.revision==expected.revision&&v.network==expected.network&&v.host==expected.host;}

#include <linux/netfilter/gta3xlwifi_loopback.h>
using EWire=gta3xlwifi_loopback_event;using Batch=NetpolicyLease::LoopbackBatch;
std::vector<EWire> eventQueue;uint64_t lostTotal=0;unsigned eventCalls=0,eventFaultAt=0,eventFault=0,eventErrorAt=0;int eventError=0,eventAck=0;bool consumeError=false,appendAtConsume=false;
extern "C" int priorIoctl(int fd,unsigned long cmd,...){
 va_list args;va_start(args,cmd);unsigned long arg=va_arg(args,unsigned long);va_end(args);
 if(cmd!=GTA3XLWIFI_LOOPBACK_GET_EVENTS)return image_ioctl(fd,cmd,arg);
 assert(files.count(fd)&&files.at(fd).path==node&&arg);++eventCalls;
 if(eventCalls==eventErrorAt&&!consumeError){errno=eventError;return -1;}
 auto*t=reinterpret_cast<gta3xlwifi_loopback_transfer*>(arg);assert(t->version==1&&t->count<=512&&bool(t->count)==bool(t->entries));
 auto*buffer=reinterpret_cast<EWire*>(static_cast<uintptr_t>(t->entries));bool consume=t->count;
 if(consume){assert(!eventQueue.empty()&&t->first_sequence==eventQueue.front().sequence);unsigned count=std::min(size_t(t->count),eventQueue.size());memcpy(buffer,eventQueue.data(),count*sizeof(EWire));eventQueue.erase(eventQueue.begin(),eventQueue.begin()+count);t->count=count;if(appendAtConsume)eventQueue.push_back({10002,110002,0,0,999,buffer[count-1].sequence+1,lostTotal});}
 else {t->count=eventQueue.size();t->first_sequence=eventQueue.empty()?0:eventQueue.front().sequence;}
 t->lost_events=lostTotal;
 if(eventCalls==eventErrorAt){errno=eventError;return -1;}
 if(eventCalls==eventFaultAt){switch(eventFault){
  case 1:t->version=2;break;case 2:t->count=513;break;case 3:t->entries=17;break;case 4:++t->first_sequence;break;case 5:t->first_sequence=0;break;case 6:t->lost_events=0;break;
  case 7:buffer[0].reserved=1;break;case 8:buffer[0].result=2;break;case 9:buffer[0].receiver_uid=buffer[0].sender_uid;break;case 10:++buffer[0].sequence;break;case 11:buffer[0].lost_events=lostTotal+1;break;case 12:buffer[1].sequence=buffer[0].sequence;break;case 13:buffer[1].lost_events=0;break;case 14:--t->count;break;default:assert(false);
 }}return eventAck;
}
EWire ewire(uint64_t seq,uint64_t lost=0){return {10001,110001,1,0,1000000000,seq,lost};}
void resetEvents(){resetLna();features=255;eventQueue.clear();lostTotal=0;eventCalls=eventFaultAt=eventFault=eventErrorAt=0;eventError=eventAck=0;consumeError=appendAtConsume=false;}
Batch sentinelEvents(){return {{{77,88,1,22,33,44}},555};}
bool untouchedEvents(const Batch&v){return v.events.size()==1&&v.events[0].senderUid==77&&v.events[0].receiverUid==88&&v.events[0].sequence==33&&v.lostEvents==555;}

#include <linux/netfilter/gta3xlwifi_packet_stats.h>
using PS=NetpolicyLease::PacketState;using PP=NetpolicyLease::PacketSnapshot;using AP=NetpolicyLease::AppSnapshot;using BT=NetpolicyLease::BankTransition;
static unsigned calls,retries,fault,error;static bool appRead;static int errorCode;
static gta3xlwifi_packet_stats_state st;
static std::vector<gta3xlwifi_packet_stats_entry> packets;
static std::vector<gta3xlwifi_app_stats_entry> apps;
static uint64_t loss,sequence;
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
 va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);
 if(cmd!=GTA3XLWIFI_STATS_GET_STATE&&cmd!=GTA3XLWIFI_STATS_READ&&cmd!=GTA3XLWIFI_STATS_SWAP&&cmd!=GTA3XLWIFI_STATS_ACK&&cmd!=GTA3XLWIFI_STATS_EDIT)return priorIoctl(fd,cmd,arg);
 assert(files.count(fd)&&arg);++calls;
 if(cmd==GTA3XLWIFI_STATS_GET_STATE){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_state*>(arg);gta3xlwifi_packet_stats_state zero{};assert(!memcmp(x,&zero,sizeof(zero)));*x=st;switch(fault){case 0:break;case 1:x->version=2;break;case 2:x->reserved=1;break;case 3:x->active_bank=2;break;case 4:x->active_epoch=0;break;case 5:x->pending_mask=4;break;case 6:x->pending_mask=1;break;case 7:x->bank_epoch[0]=9;break;case 8:x->app_count=10001;break;case 9:x->counterset_count=20001;break;case 10:x->bank_count[0]=5001;break;case 11:x->bank_epoch[1]=99;break;case 12:x->pending_mask=2;x->bank_epoch[1]=0;break;default:assert(false);}}
 else if(cmd==GTA3XLWIFI_STATS_READ){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_transfer*>(arg);assert(x->version==1&&!x->reserved&&!x->lost_updates&&!x->sequence&&x->entries);void*rows=reinterpret_cast<void*>(uintptr_t(x->entries));
  if(appRead){assert(x->kind==2&&!x->epoch&&x->count==10000);std::copy(apps.begin(),apps.end(),static_cast<gta3xlwifi_app_stats_entry*>(rows));x->count=apps.size();}
  else{assert(x->kind==1&&x->epoch==7&&x->count==5000);std::copy(packets.begin(),packets.end(),static_cast<gta3xlwifi_packet_stats_entry*>(rows));x->count=packets.size();}
  x->lost_updates=loss;x->sequence=sequence;
  switch(fault){case 0:break;case 1:x->version=2;break;case 2:x->kind=3;break;case 3:++x->epoch;break;case 4:x->reserved=1;break;case 5:x->count=10001;break;case 6:x->entries=1;break;
   case 7:if(appRead)static_cast<gta3xlwifi_app_stats_entry*>(rows)[0].reserved=1;else static_cast<gta3xlwifi_packet_stats_entry*>(rows)[0].key.counterset=2;break;
   case 8:if(appRead)static_cast<gta3xlwifi_app_stats_entry*>(rows)[1].uid=apps[0].uid;else static_cast<gta3xlwifi_packet_stats_entry*>(rows)[1].key=packets[0].key;break;
   case 9:if(appRead)std::swap(static_cast<gta3xlwifi_app_stats_entry*>(rows)[0],static_cast<gta3xlwifi_app_stats_entry*>(rows)[1]);else std::swap(static_cast<gta3xlwifi_packet_stats_entry*>(rows)[0],static_cast<gta3xlwifi_packet_stats_entry*>(rows)[1]);break;default:assert(false);}
 }else if(cmd==GTA3XLWIFI_STATS_SWAP){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_swap*>(arg);assert(x->version==1&&x->active_bank==0&&x->active_epoch==1&&!x->inactive_bank&&!x->reserved&&!x->inactive_epoch);x->active_bank=1;x->active_epoch=2;x->inactive_bank=0;x->inactive_epoch=1;st.active_bank=1;st.active_epoch=2;st.bank_epoch[1]=2;st.pending_mask=1;switch(fault){case 0:break;case 1:x->version=2;break;case 2:x->reserved=1;break;case 3:x->active_bank=0;break;case 4:x->active_epoch=3;break;case 5:x->inactive_bank=1;break;case 6:x->inactive_epoch=9;break;default:assert(false);}}
 else if(cmd==GTA3XLWIFI_STATS_ACK){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_ack*>(arg);assert(x->version==1&&x->bank==1&&x->epoch==7&&!x->reserved);}
 else{auto*x=reinterpret_cast<gta3xlwifi_packet_stats_edit*>(arg);assert(x->version==1&&x->uid==123&&!x->tag&&!x->reserved);assert((x->operation==1&&x->counterset<=1)||(x->operation==2&&!x->counterset));}
 if(retries){--retries;errno=EINTR;return -1;}if(error){errno=errorCode;return error==2?1:-1;}return 0;
}
static void resetPacket(){resetEvents();features=4096;calls=retries=fault=error=0;errorCode=0;appRead=false;st={};st.version=1;st.active_epoch=1;st.bank_epoch[0]=1;packets={{{1,0,0,2},3,4,5,6},{{1,7,1,4},8,9,10,11}};apps={{1,0,3,4,5,6},{2,0,7,8,9,10}};loss=3;sequence=4;}
int main(){
 resetPacket();{NetpolicyLease l;PS s;PP p;AP a;BT b;C(l.readPacketState(nullptr)==-EINVAL);C(l.readFrozenPacketStats(2,7,&p)==-EINVAL);C(l.readFrozenPacketStats(1,0,&p)==-EINVAL);C(l.readAppStats(nullptr)==-EINVAL);C(l.swapPacketStats(0,UINT64_MAX,&b)==-EINVAL);C(l.acknowledgePacketStats(2,7)==-EINVAL);C(l.setPacketCounterset(123,2)==-EINVAL);C(l.readPacketState(&s)==-ENOTCONN&&!calls);C(l.start()==0);C(l.readPacketState(&s)==0&&s.activeEpoch==1&&held);retries=3;C(l.readPacketState(&s)==0&&!retries&&calls==5);C(l.readFrozenPacketStats(1,7,&p)==0&&p.entries.size()==2&&p.entries[1].tag==7&&p.lostUpdates==3&&p.sequence==4&&p.epoch==7);retries=2;C(l.readFrozenPacketStats(1,7,&p)==0&&!retries);appRead=true;retries=2;C(l.readAppStats(&a)==0&&a.entries.size()==2&&a.entries[1].txBytes==10&&a.lostUpdates==3&&!retries);C(l.swapPacketStats(0,1,&b)==0&&b.activeBank==1&&b.activeEpoch==2&&b.inactiveEpoch==1);retries=2;C(l.acknowledgePacketStats(1,7)==0&&!retries);C(l.setPacketCounterset(123,0)==0&&l.setPacketCounterset(123,1)==0&&l.deleteUidPacketStats(123)==0);C(l.release()==0&&!held);C(l.readAppStats(&a)==0&&!held&&opens==1);}
 for(unsigned f=1;f<=12;f++){resetPacket();fault=f;NetpolicyLease l;PS s;s.activeEpoch=99;C(l.start()==0&&l.readPacketState(&s)==-EPROTO&&s.activeEpoch==99&&files.empty()&&held);}
 for(bool app:{false,true})for(unsigned f=1;f<=9;f++){resetPacket();fault=f;appRead=app;NetpolicyLease l;PP p;p.epoch=99;AP a;a.sequence=99;C(l.start()==0);int r=app?l.readAppStats(&a):l.readFrozenPacketStats(1,7,&p);C(r==-EPROTO&&p.epoch==99&&a.sequence==99&&files.empty()&&held);}
 for(unsigned f=1;f<=6;f++){resetPacket();fault=f;NetpolicyLease l;BT b;b.activeEpoch=99;C(l.start()==0&&l.swapPacketStats(0,1,&b)==-EPROTO&&b.activeEpoch==99&&calls==1&&files.empty()&&held);}
 for(unsigned op=0;op<3;op++){resetPacket();retries=1;NetpolicyLease l;BT b;b.activeEpoch=99;C(l.start()==0);int r=op==0?l.swapPacketStats(0,1,&b):op==1?l.setPacketCounterset(123,1):l.deleteUidPacketStats(123);C(r==-EINTR&&calls==1&&files.empty()&&held&&b.activeEpoch==99);if(!op){C(st.active_bank==1&&st.pending_mask==1);C(l.start()==0);PS state;C(l.readPacketState(&state)==0&&state.activeBank==1&&state.pendingMask==1);}}
 for(int e:{EFAULT,EBUSY,ESTALE,ENODATA,EIO,ENOMEM,ENOTTY,0}){resetPacket();error=1;errorCode=e;NetpolicyLease l;PP p;p.epoch=99;C(l.start()==0&&l.readFrozenPacketStats(1,7,&p)==-(e?e:EIO)&&p.epoch==99&&files.empty()&&held);}
 resetPacket();error=2;{NetpolicyLease l;PS s;C(l.start()==0&&l.readPacketState(&s)==-EPROTO&&files.empty()&&held);}
 for(unsigned missing:{0,4095,8192}){resetPacket();features=missing;NetpolicyLease l;PS s;C(l.start()==0&&l.readPacketState(&s)==-EOPNOTSUPP&&files.empty()&&!calls&&held);}
 resetPacket();packets.clear();apps.clear();{NetpolicyLease l;PP p;AP a;C(l.start()==0&&l.readFrozenPacketStats(1,7,&p)==0&&p.entries.empty());appRead=true;C(l.readAppStats(&a)==0&&a.entries.empty());}
 resetPacket();for(unsigned i=2;i<5000;i++)packets.push_back({{i,0,i&1,UINT32_MAX},UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX});for(unsigned i=2;i<10000;i++)apps.push_back({i+1,0,UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX});loss=sequence=UINT64_MAX;{NetpolicyLease l;PP p;AP a;C(l.start()==0&&l.readFrozenPacketStats(1,7,&p)==0&&p.entries.size()==5000&&p.entries.back().txBytes==UINT64_MAX&&p.lostUpdates==UINT64_MAX);appRead=true;C(l.readAppStats(&a)==0&&a.entries.size()==10000&&a.sequence==UINT64_MAX);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
