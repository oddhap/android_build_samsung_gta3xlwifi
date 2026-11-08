
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
extern "C" int uid_ioctl(int fd,unsigned long cmd,...){
 assert(files.count(fd)&&files.at(fd).path==node);
 va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);
 if(ioctlEintr){--ioctlEintr;errno=EINTR;return -1;}
 if(ioctlError&&cmd==errorCommand){errno=ioctlError;return -1;}
 if(cmd>=0x6750&&cmd<=0x6753){
  assert(arg==0);
  if(cmd==GTA3XLWIFI_NETPOLICY_ABI)return abi;
  if(cmd==GTA3XLWIFI_NETPOLICY_STATE)return stateOverride>=0?stateOverride:int(held);
  if(cmd==GTA3XLWIFI_NETPOLICY_HOLD)firewallAllowed=true;held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;
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
 assert(held);++lnaSets;firewallAllowed=false;if(lnaSetError&&!lnaCommitError){errno=lnaSetError;return -1;}
 std::vector<LWire> nextN,nextH;if(t->network_count)nextN.assign(n,n+t->network_count);if(t->host_count)nextH.assign(h,h+t->host_count);
 if(t->revision==lnaRevision){assert(equalLWire(nextN,netImage)&&equalLWire(nextH,hostImage));}
 else{assert(t->revision==lnaRevision+1);netImage=nextN;hostImage=nextH;lnaRevision=t->revision;}
 if(lnaEintr){--lnaEintr;errno=EINTR;return -1;}if(lnaReleaseAfterSet)held=false;if(lnaSetError){errno=lnaSetError;return -1;}return lnaAck;
}
LEntry entry(uint32_t bits,uint8_t first,bool allow){LEntry e={bits,{},allow};e.key[0]=first;return e;}
const std::vector<LEntry> network={entry(0,0,false),entry(64,1,true),entry(192,2,false)},host={entry(64,3,true),entry(192,4,true)};
std::vector<LWire> encode(const std::vector<LEntry>&v){std::vector<LWire>w(v.size());for(size_t i=0;i<v.size();i++){w[i].prefix_bits=v[i].prefixBits;memcpy(w[i].key,v[i].key.data(),24);w[i].allowed=v[i].allowed;}return w;}
void resetLna(){firewallAllowed=true;resetImage();features=127;netImage.clear();hostImage.clear();lnaRevision=0;lnaIoctls=lnaGets=lnaSets=lnaFaultAt=lnaFault=lnaErrorAt=0;lnaError=lnaSetError=lnaAck=lnaEintr=0;lnaCommitError=lnaReleaseAfterSet=false;}
void seedLna(){lnaRevision=9;netImage=encode(network);hostImage=encode(host);}
LImage sentinelLna(){return {777,{entry(192,77,true)},{entry(64,88,false)}};}
bool untouchedLna(const LImage&v){auto expected=sentinelLna();return v.revision==expected.revision&&v.network==expected.network&&v.host==expected.host;}

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
 resetLna();{Kernel k;D d(k);C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-ENOTCONN&&k.calls==0);C(d.start()==0&&held);C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0&&!held&&lnaRevision==1&&kernelRevision==1&&lnaSets==1&&setCalls==1);auto calls=k.calls;C(d.replace(image(120001),image(120001))==-EOPNOTSUPP&&k.calls==calls);C(d.replaceWithPermissions(image(120001),image(120001),wanted)==-EOPNOTSUPP&&k.calls==calls);C(d.replaceWithLocalNetwork(image(120001),image(120001),{}, {}, {})==0&&!held&&lnaRevision==2&&kernelRevision==2&&netImage.empty()&&hostImage.empty()&&kernelImage.empty());d.stop();C(files.empty()&&held);}
 for(auto fail:{1u,2u})for(bool commit:{false,true}){
  resetLna();Kernel k;D d(k);C(d.start()==0);k.failWriteAt=fail;k.commitFailure=commit;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EREMOTEIO&&held&&lnaSets==0&&setCalls==0&&lnaRevision==0&&kernelRevision==0&&k.uid[V4]==10001&&k.uid[V6]==10001);k.failWriteAt=0;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==0&&!held&&lnaRevision==1&&kernelRevision==1);
 }
 for(auto fail:{1u,2u})for(bool commit:{false,true}){
  resetLna();Kernel k;D d(k);C(d.start()==0&&d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0);k.writes=0;k.failWriteAt=fail;k.commitFailure=commit;C(d.replaceWithLocalNetwork(image(120001),image(120001),{}, {}, {})==-EREMOTEIO&&!held&&kernelRevision==1&&lnaRevision==1&&setCalls==1&&lnaSets==1&&k.uid[V4]==110001&&k.uid[V6]==110001);
 }
 resetLna();{Kernel k;D d(k);C(d.start()==0);auto calls=k.calls;auto bad=network;bad[0].key[23]=1;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,bad,host)==-EINVAL&&k.calls==calls&&lnaSets==0&&setCalls==0&&held);bad=network;bad.push_back(network[0]);C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,bad,host)==-EEXIST&&k.calls==calls);C(d.replaceWithLocalNetwork(image(110001),image(110001),{{1,0}},network,host)==-EINVAL&&k.calls==calls);}
 for(bool commit:{false,true}){
  resetLna();Kernel k;D d(k);C(d.start()==0);lnaSetError=EIO;lnaCommitError=commit;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&lnaRevision==(commit?1:0)&&kernelRevision==0&&setCalls==0);auto calls=k.calls;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==-ENOTCONN&&k.calls==calls);
 }
 for(bool commit:{false,true}){
  resetLna();Kernel k;D d(k);C(d.start()==0);setError=EIO;commitThenError=commit;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&lnaRevision==1&&kernelRevision==(commit?1:0));
 }
 // LNA read1,2 before-image;3 setter metadata;4,5 post-write metadata/data.
 for(unsigned call:{3u,4u,5u}){resetLna();Kernel k;D d(k);C(d.start()==0);lnaErrorAt=call;lnaError=EFAULT;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&setCalls==0);}
 for(unsigned fault:{16u,17u}){resetLna();Kernel k;D d(k);C(d.start()==0);lnaFaultAt=5;lnaFault=fault;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&setCalls==0&&lnaRevision==1);}
 resetLna();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0);hostImage[0].allowed=0;auto writes=k.writes;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetLna();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0);kernelImage[0].permissions=1;auto writes=k.writes;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetLna();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0);k.uid[V6]=99999;auto writes=k.writes;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetLna();{Kernel k;D d(k);C(d.start()==0);ioctlError=EIO;errorCommand=GTA3XLWIFI_NETPOLICY_RELEASE;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&lnaRevision==1&&kernelRevision==1);}
 resetLna();{Kernel k;D d(k);C(d.start()==0);auto root=wanted;root.insert(root.begin(),{0,4});C(d.replaceWithLocalNetwork(image(110001),image(110001),root,network,host)==0&&!held&&kernelImage[0].uid==0&&kernelImage[0].permissions==4);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
