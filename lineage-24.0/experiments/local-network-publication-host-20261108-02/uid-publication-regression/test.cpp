
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

#include "Gta3xlwifiUidPolicyTransaction.h"
#include <atomic>
#include <climits>
#include <condition_variable>
#include <sstream>
using namespace android::net::gta3xlwifi;
using P=UidPolicyTransaction;using Image=UidChainProgram::Image;
struct Kernel:IptablesRestoreInterface{
 std::map<IptablesTarget,std::map<std::string,std::string>> tables;
 unsigned calls=0,writes=0,reads=0,failWriteAt=0,failAfter=0,badReadAt=0;
 bool commitFailure=true,badHook=false,pause=false,blocked=false,resume=false;
 std::mutex gate;std::condition_variable cv;
 Kernel(){for(auto f:{V4,V6}){for(int i=1;i<=9;i++)tables[f]["g24_uid_"+std::to_string(i)]="";
  for(auto name:{"g24_meter_deny","g24_meter_allow","g24_data_saver","g24_owner_in","g24_owner_out"})tables[f][name]="";}}
 int execute(IptablesTarget f,const std::string& command,std::string* output)override{
  assert((f==V4||f==V6)&&held&&opens==1);++calls;
  for(auto chain:{"INPUT","FORWARD","OUTPUT"})if(command=="*filter\n-S "+std::string(chain)+"\nCOMMIT\n"){
   assert(output);*output="-P "+std::string(chain)+" ACCEPT\n";
   if(!badHook)*output+="-A "+std::string(chain)+" -m gta3xlwifi_guard -j DROP\n";
   *output+="-A "+std::string(chain)+" -j fw_test\n";return 0;
  }
  std::istringstream stream(command);std::string line;assert(std::getline(stream,line)&&line=="*filter");
  auto next=tables[f];std::string result;bool write=false;
  while(std::getline(stream,line)){
   if(line=="COMMIT")break;
   if(line.rfind("-S g24_",0)==0){assert(output&&!write);auto name=line.substr(3);result+="-N "+name+"\n"+tables[f][name];continue;}
   assert(!output);write=true;
   if(line.rfind(":g24_",0)==0){auto end=line.find(' ');assert(line.substr(end)==" -");next[line.substr(1,end-1)]="";continue;}
   assert(line.rfind("-A g24_",0)==0);auto end=line.find(' ',3);auto name=line.substr(3,end-3);assert(next.count(name));
   if(line.size()>=10&&line.substr(line.size()-10)==" -j REJECT")line+=" --reject-with "+std::string(f==V4?"icmp-port-unreachable":"icmp6-port-unreachable");
   next[name]+=line+"\n";
  }
  assert(line=="COMMIT"&&!std::getline(stream,line));
  if(output){++reads;*output=reads==badReadAt?"bad":result;return 0;}
  assert(write);++writes;
  if(pause&&f==V6){std::unique_lock<std::mutex> lock(gate);blocked=true;cv.notify_all();cv.wait(lock,[&]{return resume;});pause=false;}
  bool fail=writes==failWriteAt||(failAfter&&writes>=failAfter);
  if(!fail||commitFailure)tables[f]=std::move(next);
  return fail?-1:0;
 }
};
UidPolicy configured(){UidPolicy p;assert(p.setChainEnabled(1,true)==0);assert(p.replaceUidChain(1,{10001})==0);p.setDataSaver(true);assert(p.replaceUidChain(10,{10001})==0);return p;}

UidPermissionState permissions(uint32_t mask=4){UidPermissionState p;assert(p.set(10001,mask)==0);return p;}
int main(){
 resetImage();{Kernel k;P p(k);uint32_t mask=777;C(p.getUidPermission(10001,&mask)==-EAGAIN&&mask==777);C(p.setUidPermission(10001,4)==-EAGAIN);C(p.replace(configured(),permissions())==-ENOTCONN&&k.calls==0);
 C(p.start()==0&&held);C(p.replace(configured(),permissions())==0&&!held&&kernelRevision==1);C(p.getUidPermission(10001,&mask)==0&&mask==4);C(p.getUidPermission(10001,nullptr)==-EINVAL);
 C(p.setUidPermission(10001,1)==0&&kernelRevision==2&&!held);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 C(p.setDataSaver(false)==0&&kernelRevision==3);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 C(p.replace(configured())==0&&kernelRevision==4);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 auto calls=k.calls;auto io=imageIoctls;C(p.setUidPermission(-1,1)==-EINVAL);C(p.setUidPermission(10001,128)==-EINVAL);C(k.calls==calls&&imageIoctls==io);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 UidPermissionState huge;for(int i=0;i<65537;i++)assert(huge.set(i,1)==0);C(p.replace(configured(),huge)==-E2BIG&&k.calls==calls&&imageIoctls==io);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 C(p.setUidPermission(10001,0)==0&&kernelImage.empty());C(p.getUidPermission(10001,&mask)==0&&mask==0);
 C(p.setUidPermission(10001,4)==0);C(p.removeUid(10001)==0&&kernelImage.empty());C(p.getUidPermission(10001,&mask)==0&&mask==0);int32_t rule=777;C(p.getUidRule(1,10001,&rule)==0&&rule==UidPolicy::Deny);
 p.stop();mask=777;C(p.getUidPermission(10001,&mask)==-EAGAIN&&mask==777&&held&&files.empty());}
 for(bool prior:{false,true})for(auto failure:{1u,2u})for(bool committed:{false,true}){
  resetImage();Kernel k;P p(k);C(p.start()==0);if(prior)C(p.replace(UidPolicy{},permissions(1))==0);auto old=k.tables;auto oldImage=kernelImage;k.writes=0;k.failWriteAt=failure;k.commitFailure=committed;
  C(p.replace(configured(),permissions())==-EREMOTEIO&&held&&files.empty()&&k.tables==old&&equalWire(kernelImage,oldImage));uint32_t mask=777;bool enabled=true;
  C(p.getUidPermission(10001,&mask)==-EAGAIN&&mask==777);C(p.getChainEnabled(1,&enabled)==-EAGAIN&&enabled);
 }
 for(bool commit:{false,true}){
  resetImage();Kernel k;P p(k);C(p.start()==0);setError=EIO;commitThenError=commit;C(p.replace(configured(),permissions())==-EUCLEAN&&held&&files.empty());uint32_t mask=777;C(p.getUidPermission(10001,&mask)==-EAGAIN&&mask==777);C(p.isNetworkingBlocked(10001,false)==-EAGAIN);
  setError=0;C(p.start()==0&&held);C(p.replace(configured(),permissions(1))==0&&!held);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 }
 resetImage();{Kernel k;P p(k);C(p.start()==0&&p.replace(configured(),permissions())==0);auto next=configured();assert(next.setUidRule(1,10002,UidPolicy::Allow)==0);k.pause=true;int result=777;std::thread writer([&]{result=p.replace(next,permissions(1));});{std::unique_lock<std::mutex> lock(k.gate);k.cv.wait(lock,[&]{return k.blocked;});}
 C(held&&kernelImage[0].permissions==4);std::atomic<bool> begun=false,done=false;uint32_t value=777;int query=777;std::thread reader([&]{begun=true;query=p.getUidPermission(10001,&value);done=true;});while(!begun.load())std::this_thread::yield();C(!done.load());{std::lock_guard<std::mutex> lock(k.gate);k.resume=true;k.cv.notify_all();}writer.join();reader.join();C(result==0&&query==0&&value==1&&!held&&done.load());C(p.isNetworkingBlocked(10002,false)==0);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
