
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
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
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
int main(){
 static_assert(sizeof(gta3xlwifi_lna_transfer)==40&&sizeof(LWire)==32);static_assert(GTA3XLWIFI_LNA_SET_IMAGE==0x40286757&&GTA3XLWIFI_LNA_GET_IMAGE==0xc0286758);
 resetLna();{NetpolicyLease l;LImage value=sentinelLna();uint64_t revision=888;
 C(l.readLocalNetwork(nullptr)==-EINVAL);C(l.readLocalNetwork(&value)==-ENOTCONN&&untouchedLna(value));C(l.replaceLocalNetwork(0,network,host,nullptr)==-EINVAL);C(l.replaceLocalNetwork(UINT64_MAX,network,host,&revision)==-EOVERFLOW&&lnaIoctls==0);C(l.replaceLocalNetwork(0,network,host,&revision)==-ENOTCONN&&revision==888);
 C(l.start()==0);C(l.readLocalNetwork(&value)==0&&value.revision==0&&value.network.empty()&&value.host.empty()&&held);
 C(l.replaceLocalNetwork(0,network,host,&revision)==0&&revision==1&&held&&opens==1);C(l.readLocalNetwork(&value)==0&&value.revision==1&&value.network==network&&value.host==host);
 C(l.replaceLocalNetwork(1,{},host,&revision)==0&&revision==2&&netImage.empty());C(l.readLocalNetwork(&value)==0&&value.network.empty()&&value.host==host);
 C(l.replaceLocalNetwork(2,network,{},&revision)==0&&revision==3&&hostImage.empty());C(l.readLocalNetwork(&value)==0&&value.network==network&&value.host.empty());
 C(l.replaceLocalNetwork(3,{}, {},&revision)==0&&revision==4);C(l.readLocalNetwork(&value)==0&&value.revision==4&&value.network.empty()&&value.host.empty());
 }
 for(unsigned missing:{0u,7u,32u,64u,119u}){resetLna();features=missing;NetpolicyLease l;LImage v=sentinelLna();C(l.start()==0);C(l.readLocalNetwork(&v)==-EOPNOTSUPP&&untouchedLna(v)&&files.empty()&&held&&lnaIoctls==0);}
 // Store-only feature is enough for this primitive, never a readiness assertion.
 resetLna();features=8;{NetpolicyLease l;LImage v;C(l.start()==0&&l.readLocalNetwork(&v)==0&&held);}
 for(unsigned fault:{1u,2u,3u,4u,5u,6u,8u}){resetLna();seedLna();lnaFaultAt=1;lnaFault=fault;NetpolicyLease l;LImage v=sentinelLna();C(l.start()==0);C(l.readLocalNetwork(&v)==-EPROTO&&untouchedLna(v)&&files.empty()&&held);}
 for(unsigned fault:{1u,2u,3u,4u,5u,6u,7u,8u,9u,10u,11u,12u,13u,14u,15u,18u,19u}){resetLna();seedLna();lnaFaultAt=2;lnaFault=fault;NetpolicyLease l;LImage v=sentinelLna();C(l.start()==0);C(l.readLocalNetwork(&v)==-EPROTO&&untouchedLna(v)&&files.empty()&&held);}
 for(unsigned call:{1u,2u}){resetLna();seedLna();lnaErrorAt=call;lnaError=EFAULT;NetpolicyLease l;LImage v=sentinelLna();C(l.start()==0);C(l.readLocalNetwork(&v)==-EFAULT&&untouchedLna(v)&&files.empty()&&held);}
 resetLna();{NetpolicyLease l;uint64_t rev=888;C(l.start()==0&&l.release()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EBUSY&&rev==888&&files.empty()&&held&&lnaSets==0);}
 resetLna();seedLna();{NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(8,network,host,&rev)==-ESTALE&&rev==888&&files.empty()&&held&&lnaSets==0);}
 for(bool commit:{false,true}){resetLna();lnaSetError=EIO;lnaCommitError=commit;NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EIO&&rev==888&&files.empty()&&held&&lnaRevision==(commit?1:0));}
 resetLna();lnaEintr=1;{NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==0&&rev==1&&lnaRevision==1&&lnaSets==2&&held);}
 resetLna();lnaAck=1;{NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EPROTO&&rev==888&&lnaRevision==1&&held&&files.empty());}
 for(unsigned call:{2u,3u}){resetLna();lnaErrorAt=call;lnaError=ESTALE;NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-ESTALE&&rev==888&&held&&files.empty()&&lnaRevision==1);}
 for(unsigned fault:{7u,16u,17u}){resetLna();lnaFaultAt=3;lnaFault=fault;NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EPROTO&&rev==888&&held&&files.empty()&&lnaRevision==1);}
 resetLna();lnaReleaseAfterSet=true;{NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EPROTO&&rev==888&&held&&files.empty());}
 // Every prefix boundary, and the first ignored bit, exercise canonical wire keys.
 resetLna();{NetpolicyLease l;uint64_t rev=0;C(l.start()==0);
 for(unsigned bits=0;bits<=192;bits++){LEntry e={bits,{},bool(bits&1)};if(bits)e.key[(bits-1)/8]=1u<<(7-(bits-1)%8);C(l.replaceLocalNetwork(rev,{e},{},&rev)==0&&rev==bits+1&&held);LImage v;C(l.readLocalNetwork(&v)==0&&v.network==std::vector<LEntry>{e}&&v.host.empty());if(bits<192){e.key[bits/8]|=1u<<(7-bits%8);unsigned before=lnaIoctls;C(l.replaceLocalNetwork(rev,{e},{},&rev)==-EINVAL&&lnaIoctls==before&&opens==1&&held);}}
 for(auto invalid:std::vector<std::vector<LEntry>>{{entry(193,0,true)},{entry(0,1,true)},{entry(64,2,true),entry(64,1,false)},{entry(64,1,true),entry(64,1,false)},std::vector<LEntry>(1001,entry(0,0,true))}){unsigned before=lnaIoctls;C(l.replaceLocalNetwork(rev,invalid,{},&rev)==-EINVAL&&lnaIoctls==before);C(l.replaceLocalNetwork(rev,{},invalid,&rev)==-EINVAL&&lnaIoctls==before);}
 }
 resetLna();{NetpolicyLease l;uint64_t rev=0;C(l.start()==0);std::vector<LEntry> many;for(unsigned i=0;i<1000;i++){auto e=entry(192,0,i&1);e.key[22]=i>>8;e.key[23]=i&255;many.push_back(e);}C(l.replaceLocalNetwork(0,many,many,&rev)==0&&rev==1);LImage v;C(l.readLocalNetwork(&v)==0&&v.network==many&&v.host==many);std::vector<std::thread> threads;for(int i=0;i<16;i++)threads.emplace_back([&l,&many]{LImage v;assert(l.readLocalNetwork(&v)==0&&v.network==many&&v.host==many&&v.revision==1);});for(auto&t:threads)t.join();C(held&&opens==1);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
