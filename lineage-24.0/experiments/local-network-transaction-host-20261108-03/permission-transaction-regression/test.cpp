
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
unsigned cases=0;bool firewallAllowed=true;
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
 if(path==node){assert(opens==0);++opens;held=true;firewallAllowed=true;}
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
  if(cmd==GTA3XLWIFI_NETPOLICY_HOLD){firewallAllowed=true;}held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;
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
 assert(cmd==GTA3XLWIFI_UID_SET_IMAGE&&held);++setCalls;firewallAllowed=false;
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
void resetImage(){firewallAllowed=true;reset();kernelImage.clear();kernelRevision=0;features=7;imageIoctls=getCalls=setCalls=getFaultAt=getFault=getErrorAt=getError=setError=setAck=setEintrAfterCommit=0;commitThenError=releaseAfterSet=false;}
void seed(){kernelRevision=9;kernelImage={{10001,4},{110001,127}};}
ImageValue sentinel(){return {777,{{555,1}}};}
bool untouched(const ImageValue&v){return v.revision==777&&v.entries==std::vector<EntryValue>{{555,1}};}
const std::vector<EntryValue> wanted={{10001,4},{110001,127}};

#include "Gta3xlwifiDualStackUidChains.h"
using D=android::net::gta3xlwifi::DualStackUidChains;
using Chains=android::net::gta3xlwifi::CheckedUidChains;
D::Image image(unsigned uid){return {{"g24_uid",{{Chains::UidRange{uid,uid},Chains::Verdict::Return},{std::nullopt,Chains::Verdict::Drop}}}};}
struct Kernel:IptablesRestoreInterface{
 std::map<IptablesTarget,unsigned> uid{{V4,10001},{V6,10001}};
 std::map<std::pair<IptablesTarget,std::string>,bool> guards;
 Kernel(){for(auto f:{V4,V6})for(auto c:{"INPUT","FORWARD","OUTPUT"})guards[{f,c}]=true;}
 void missing(){for(auto& pair:guards)pair.second=false;}
 unsigned calls=0,writes=0,uidReads=0,failWriteAt=0,failAfter=0,badUidReadAt=0;
 int badFamily=0;std::string badChain,overrideText;bool changeHooksOnWrite=false,commitFailure=true;
 int execute(IptablesTarget f,const std::string& command,std::string* output)override{
  assert(f==V4||f==V6);assert(firewallAllowed&&held&&opens==1);++calls;
  for(auto chain:{"INPUT","FORWARD","OUTPUT"}){
   if(command=="*filter\n-S "+std::string(chain)+"\nCOMMIT\n"){
    assert(output);*output="-P "+std::string(chain)+" ACCEPT\n";if(guards[{f,chain}])*output+="-A "+std::string(chain)+" -m gta3xlwifi_guard -j DROP\n";*output+="-A "+std::string(chain)+" -j fw_test\n";
    if(int(f)==badFamily&&chain==badChain)*output=overrideText;
    return 0;
   }
  }
  if(command=="*filter\n-S g24_uid\nCOMMIT\n"){
   assert(output);++uidReads;
   *output="-N g24_uid\n-A g24_uid -m owner --uid-owner "+std::to_string(uid[f])+" -j RETURN\n-A g24_uid -j DROP\n";
   if(uidReads==badUidReadAt)*output="bad";
   return 0;
  }
  if(command.rfind("*filter\n-I ",0)==0){
   assert(output==nullptr);++writes;bool fail=writes==failWriteAt||(failAfter&&writes>=failAfter);
   std::string expected="*filter\n";
   for(auto c:{"INPUT","FORWARD","OUTPUT"})if(!guards[{f,c}])expected+="-I "+std::string(c)+" 1 -m gta3xlwifi_guard -j DROP\n";
   expected+="COMMIT\n";assert(command==expected);
   if(!fail||commitFailure)for(auto c:{"INPUT","FORWARD","OUTPUT"})guards[{f,c}]=true;
   return fail?-1:0;
  }
  assert(output==nullptr);assert(command.rfind("*filter\n:g24_uid -\n-A g24_uid -m owner --uid-owner ",0)==0);
  auto pos=command.find("--uid-owner ")+12;unsigned value=std::stoul(command.substr(pos));++writes;
  bool fail=writes==failWriteAt||(failAfter&&writes>=failAfter);
  if(!fail||commitFailure)uid[f]=value;
  if(changeHooksOnWrite){badFamily=V6;badChain="OUTPUT";overrideText="-P OUTPUT ACCEPT\n-A OUTPUT -j ACCEPT\n";}
  return fail?-1:0;
 }
};

int main(){
 resetImage();{Kernel k;D d(k);C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-ENOTCONN&&k.calls==0);C(d.start()==0&&held);C(d.replaceWithPermissions(image(110001),image(110001),wanted)==0&&!held&&kernelRevision==1&&setCalls==1&&k.uid[V4]==110001&&k.uid[V6]==110001);auto calls=k.calls;C(d.replace(image(120001),image(120001))==-EOPNOTSUPP&&k.calls==calls&&!held);C(d.replaceWithPermissions(image(120001),image(120001),{})==0&&!held&&kernelRevision==2&&kernelImage.empty());d.stop();C(files.empty()&&held);}
 for(auto fail:{1u,2u})for(bool commit:{false,true}){
  resetImage();Kernel k;D d(k);C(d.start()==0);k.failWriteAt=fail;k.commitFailure=commit;
  C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EREMOTEIO&&held&&kernelRevision==0&&setCalls==0&&k.uid[V4]==10001&&k.uid[V6]==10001);
  k.failWriteAt=0;C(d.replaceWithPermissions(image(120001),image(120001),wanted)==0&&!held&&kernelRevision==1);
 }
 for(auto fail:{1u,2u})for(bool commit:{false,true}){
  resetImage();Kernel k;D d(k);C(d.start()==0&&d.replaceWithPermissions(image(110001),image(110001),wanted)==0);k.writes=0;k.failWriteAt=fail;k.commitFailure=commit;
  C(d.replaceWithPermissions(image(120001),image(120001),{})==-EREMOTEIO&&!held&&kernelRevision==1&&setCalls==1&&k.uid[V4]==110001&&k.uid[V6]==110001);
 }
 resetImage();{Kernel k;D d(k);C(d.start()==0);auto bad=image(110001);bad[0].name="foreign";auto calls=k.calls;C(d.replaceWithPermissions(bad,image(110001),wanted)==-EINVAL&&k.calls==calls&&setCalls==0);C(d.replaceWithPermissions(image(110001),image(110001),{{1,0}})==-EINVAL&&k.calls==calls);C(d.replaceWithPermissions(image(110001),image(110001),{{2,1},{1,1}})==-EINVAL&&k.calls==calls);}
 for(bool commit:{false,true}){
  resetImage();Kernel k;D d(k);C(d.start()==0);setError=EIO;commitThenError=commit;
  C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty()&&kernelRevision==(commit?1:0));auto calls=k.calls;C(d.replaceWithPermissions(image(120001),image(120001),{})==-ENOTCONN&&k.calls==calls);
 }
 for(int failure:{1,2,3}){
  resetImage();Kernel k;D d(k);C(d.start()==0);getErrorAt=failure+2;getError=EFAULT;
  // Before-image GETs1,2; setter pre-metadata3; post-write metadata4; data5.
  C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty());
 }
 resetImage();{Kernel k;D d(k);C(d.start()==0);k.changeHooksOnWrite=true;C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty()&&setCalls==0);}
 resetImage();{Kernel k;D d(k);C(d.start()==0);k.failAfter=2;C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty()&&setCalls==0);}
 resetImage();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithPermissions(image(110001),image(110001),wanted)==0);kernelImage[0].permissions=1;auto writes=k.writes;C(d.replaceWithPermissions(image(120001),image(120001),wanted)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetImage();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithPermissions(image(110001),image(110001),wanted)==0);k.uid[V6]=99999;auto writes=k.writes;C(d.replaceWithPermissions(image(120001),image(120001),wanted)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetImage();{Kernel k;D d(k);C(d.start()==0);ioctlError=EIO;errorCommand=GTA3XLWIFI_NETPOLICY_RELEASE;C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty()&&kernelRevision==1);}
 resetImage();{Kernel k;D d(k);C(d.start()==0);auto root=wanted;root.insert(root.begin(),{0,4});C(d.replaceWithPermissions(image(110001),image(110001),root)==0&&!held&&kernelImage[0].uid==0&&kernelImage[0].permissions==4);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
