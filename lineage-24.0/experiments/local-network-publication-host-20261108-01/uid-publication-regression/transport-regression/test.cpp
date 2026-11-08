
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
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
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
int main(){
 static_assert(sizeof(gta3xlwifi_uid_permission_transfer)==24&&sizeof(Wire)==8);
 static_assert(_IOC_SIZE(GTA3XLWIFI_UID_SET_IMAGE)==24);
 resetImage();{NetpolicyLease l;ImageValue value=sentinel();uint64_t revision=888;
 C(l.readUidPermissions(nullptr)==-EINVAL);C(l.readUidPermissions(&value)==-ENOTCONN&&untouched(value));
 C(l.replaceUidPermissions(0,wanted,nullptr)==-EINVAL);C(l.replaceUidPermissions(0,wanted,&revision)==-ENOTCONN&&revision==888);
 C(l.replaceUidPermissions(UINT64_MAX,wanted,&revision)==-EOVERFLOW&&imageIoctls==0);
 C(l.start()==0);C(l.readUidPermissions(&value)==0&&value.revision==0&&value.entries.empty()&&held);
 int before=imageIoctls;
 for(auto invalid:std::vector<std::vector<EntryValue>>{{{-1,1}},{{1,0}},{{1,128}},{{2,1},{1,1}},{{1,1},{1,2}},std::vector<EntryValue>(65537,{1,1})}){
  C(l.replaceUidPermissions(0,invalid,&revision)==-EINVAL&&imageIoctls==before&&held&&opens==1&&revision==888);
 }
 C(l.replaceUidPermissions(0,wanted,&revision)==0&&revision==1&&held&&opens==1&&setCalls==1);
 C(l.readUidPermissions(&value)==0&&value.revision==1&&value.entries==wanted&&held);
 C(l.replaceUidPermissions(1,{},&revision)==0&&revision==2&&kernelImage.empty()&&held);
 C(l.readUidPermissions(&value)==0&&value.revision==2&&value.entries.empty());
 C(l.replaceUidPermissions(2,wanted,&revision)==0&&revision==3&&held); // semantic rollback advances generation
 std::vector<std::thread> threads;for(int i=0;i<16;i++)threads.emplace_back([&l]{ImageValue v;assert(l.readUidPermissions(&v)==0&&v.revision==3&&v.entries==wanted);});for(auto&t:threads)t.join();C(held&&opens==1);
 }
 C(files.empty()&&held);
 for(int missing:{0,1,3,5,6}){resetImage();features=missing;NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);C(l.readUidPermissions(&v)==-EOPNOTSUPP&&untouched(v)&&files.empty()&&held);}
 resetImage();{NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);ioctlError=ENOTTY;errorCommand=GTA3XLWIFI_UID_FEATURES;C(l.readUidPermissions(&v)==-ENOTTY&&untouched(v)&&held&&files.empty());}
 // Each malformed metadata response is rejected before trusting a size/pointer.
 for(int fault:{1,2,3,10}){resetImage();seed();getFaultAt=1;getFault=fault;NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);C(l.readUidPermissions(&v)==-EPROTO&&untouched(v)&&files.empty()&&held);}
 for(int fault:{1,2,3,4,5,6,7,9,10}){resetImage();seed();getFaultAt=2;getFault=fault;NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);C(l.readUidPermissions(&v)==-EPROTO&&untouched(v)&&files.empty()&&held);}
 for(int call:{1,2}){resetImage();seed();getErrorAt=call;getError=EFAULT;NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);C(l.readUidPermissions(&v)==-EFAULT&&untouched(v)&&files.empty()&&held);}
 resetImage();{NetpolicyLease l;uint64_t revision=888;C(l.start()==0&&l.release()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EBUSY&&revision==888&&setCalls==0&&held&&files.empty());}
 resetImage();seed();{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(8,wanted,&revision)==-ESTALE&&revision==888&&setCalls==0&&held&&files.empty());}
 for(bool commit:{false,true}){resetImage();setError=EIO;commitThenError=commit;NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EIO&&revision==888&&kernelRevision==(commit?1:0)&&files.empty()&&held);}
 resetImage();setEintrAfterCommit=1;{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==0&&revision==1&&kernelRevision==1&&setCalls==2&&held);}
 resetImage();setAck=1;{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EPROTO&&revision==888&&kernelRevision==1&&held&&files.empty());}
 for(int call:{2,3}){resetImage();getErrorAt=call;getError=ESTALE;NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-ESTALE&&revision==888&&kernelRevision==1&&held&&files.empty());}
 for(int call:{2,3}){resetImage();getFaultAt=call;getFault=4;NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EPROTO&&revision==888&&kernelRevision==1&&held&&files.empty());}
 resetImage();getFaultAt=3;getFault=8;{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EPROTO&&revision==888&&kernelRevision==1&&held&&files.empty());}
 resetImage();releaseAfterSet=true;{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EPROTO&&revision==888&&held&&files.empty());}
 resetImage();{NetpolicyLease l;C(l.start()==0);std::vector<EntryValue> many;for(int32_t i=0;i<65536;i++)many.push_back({2*i,1});uint64_t revision=0;ImageValue v;C(l.replaceUidPermissions(0,many,&revision)==0&&revision==1);C(l.readUidPermissions(&v)==0&&v.entries==many&&v.revision==1&&held);}
 C(files.empty()&&held);
 printf("passed_cases=%u\n",cases);
}
