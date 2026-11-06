
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
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
 assert(files.count(fd)&&files.at(fd).path==node);
 va_list v;va_start(v,cmd);assert(va_arg(v,unsigned long)==0);va_end(v);
 assert(cmd>=0x6750&&cmd<=0x6753);
 if(ioctlEintr){--ioctlEintr;errno=EINTR;return -1;}
 if(ioctlError&&cmd==errorCommand){if(commitError&&cmd==GTA3XLWIFI_NETPOLICY_RELEASE)held=false;errno=ioctlError;return -1;}
 if(cmd==GTA3XLWIFI_NETPOLICY_ABI)return abi;
 if(cmd==GTA3XLWIFI_NETPOLICY_STATE)return stateOverride>=0?stateOverride:int(held);
 held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;
}
void reset(){assert(files.empty()&&opens==0);closes=0;openError=statError=fsError=readError=0;
 openEintr=readEintr=ioctlEintr=0;abi=1;ioctlError=0;errorCommand=0;stateOverride=-1;ack=0;
 held=true;wrongType=wrongSysfs=commitError=closeEintr=false;nodeUid=sysfsUid=nodeGid=0;mode=0400;minorNumber=64;text="10:64\n";chunk=100;}

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
int main(){
 Image image{{"sentinel",{}}},sentinel=image;UidPolicy empty;
 C(P::compile(empty,nullptr)==-EINVAL);C(P::compile(empty,&image)==0&&image.size()==12);
 UidPolicy aggregate;std::vector<int32_t> many;for(int i=0;i<10000;i++)many.push_back(10000+2*i);
 assert(aggregate.setChainEnabled(1,true)==0&&aggregate.replaceUidChain(1,many)==0&&aggregate.replaceUidChain(11,many)==0);
 C(UidChainProgram::ordinary(aggregate,&image)==0);C(MeteredChainProgram::compile(aggregate,&image)==0);image=sentinel;
 C(P::compile(aggregate,&image)==-E2BIG&&image==sentinel);
 reset();{
  Kernel k;P p(k);bool enabled=true;int32_t rule=777;uint32_t reason=777;
  C(p.getChainEnabled(1,&enabled)==-EAGAIN&&enabled);C(p.getUidRule(1,10001,&rule)==-EAGAIN&&rule==777);C(p.blockedReasons(10001,&reason)==-EAGAIN&&reason==777);C(p.isNetworkingBlocked(10001,true)==-EAGAIN);
  C(p.replace(empty)==-ENOTCONN&&k.calls==0);C(p.setDataSaver(true)==-EAGAIN);
  C(p.start()==0&&held);C(p.start()==-EALREADY&&held);C(p.setUidRule(1,10001,UidPolicy::Allow)==-EAGAIN&&k.writes==0);
  C(p.replace(configured())==0&&!held&&k.writes==2&&k.tables[V4].size()==12&&k.tables[V6].size()==12);
  C(p.getChainEnabled(1,&enabled)==0&&enabled);C(p.getUidRule(1,10001,&rule)==0&&rule==UidPolicy::Allow);C(p.isNetworkingBlocked(10001,true)==0);C(p.isNetworkingBlocked(10002,true)==1);
  C(p.setUidRule(1,10002,UidPolicy::Allow)==0);C(p.setUidRule(10,10002,UidPolicy::Allow)==0&&p.isNetworkingBlocked(10002,true)==0);
  C(p.setUidRule(11,10002,UidPolicy::Deny)==0&&p.isNetworkingBlocked(10002,true)==1&&p.isNetworkingBlocked(10002,false)==0);
  C(p.removeUid(10002)==0&&p.isNetworkingBlocked(10002,false)==1);
  C(p.setChainEnabled(1,false)==0&&p.isNetworkingBlocked(10002,false)==0);C(p.setDataSaver(false)==0&&p.isNetworkingBlocked(10002,true)==0);
  C(p.replaceUidChain(12,{10003,10004})==0&&p.getUidRule(12,10003,&rule)==0&&rule==UidPolicy::Deny);
  auto calls=k.calls;C(p.setUidRule(13,10001,UidPolicy::Allow)==-EINVAL);C(p.setUidRule(1,-1,UidPolicy::Allow)==-EINVAL);C(p.setUidRule(1,10001,99)==-EINVAL);C(p.replaceUidChain(1,{10001,-1})==-EINVAL);C(p.removeUid(-1)==-EINVAL);C(p.setChainEnabled(0,true)==-EINVAL);C(k.calls==calls);
  C(p.replace(aggregate)==-E2BIG&&k.calls==calls&&p.isNetworkingBlocked(10002,true)==0);
  enabled=true;C(p.getChainEnabled(0,&enabled)==-EINVAL&&enabled);rule=777;C(p.getUidRule(1,-1,&rule)==-EINVAL&&rule==777);reason=777;C(p.blockedReasons(-1,&reason)==-EINVAL&&reason==777);
  C(p.start()==-EALREADY&&p.isNetworkingBlocked(10002,true)==0);
  p.stop();C(held&&files.empty()&&p.isNetworkingBlocked(10001,true)==-EAGAIN);p.stop();C(closes==1);C(p.start()==0&&held&&p.isNetworkingBlocked(10001,true)==-EAGAIN);C(p.replace(configured())==0&&!held);
 }
 C(held&&files.empty());
 // Both families, acknowledgements after possible commit, first/later updates.
 for(bool prior:{false,true})for(unsigned failure:{1u,2u})for(bool committed:{false,true}){
  reset();Kernel k;P p(k);C(p.start()==0);if(prior)C(p.replace(empty)==0);
  auto old=k.tables;k.writes=0;k.failWriteAt=failure;k.commitFailure=committed;
  C(p.replace(configured())==-EREMOTEIO&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);C(k.tables==old);
  C(p.replace(empty)==-ENOTCONN);k.failWriteAt=0;C(p.start()==0&&held);C(p.replace(configured())==0&&!held&&p.isNetworkingBlocked(10001,true)==0);
 }
 reset();{Kernel k;P p(k);C(p.start()==0&&p.replace(empty)==0);k.writes=0;k.failAfter=2;C(p.replace(configured())==-EUCLEAN&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);}
 reset();{Kernel k;P p(k);C(p.start()==0&&p.replace(empty)==0);k.badHook=true;C(p.replace(configured())==-EPROTO&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);}
 reset();{Kernel k;P p(k);C(p.start()==0&&p.replace(empty)==0);k.badReadAt=k.reads+1;C(p.replace(configured())==-EPROTO&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);}
 reset();{Kernel k;P p(k);C(p.start()==0);ioctlError=EIO;errorCommand=GTA3XLWIFI_NETPOLICY_RELEASE;commitError=true;C(p.replace(configured())==-EUCLEAN&&held&&files.empty());C(p.isNetworkingBlocked(10001,true)==-EAGAIN);}
 reset();abi=2;{Kernel k;P p(k);C(p.start()==-EPROTO&&held&&files.empty());C(p.replace(empty)==-ENOTCONN);}
 // Real owner mutex serializes concurrent read/modify/commit operations.
 reset();{Kernel k;P p(k);C(p.start()==0&&p.replace(configured())==0);std::vector<std::thread> threads;
  for(int i=0;i<24;i++)threads.emplace_back([&,i]{assert(p.setUidRule(1,20000+i,UidPolicy::Allow)==0);});
  for(auto& t:threads)t.join();for(int i=0;i<24;i++){int32_t rule=0;C(p.getUidRule(1,20000+i,&rule)==0&&rule==UidPolicy::Allow);}C(k.tables[V4].size()==12&&k.tables[V4]==k.tables[V6]);
 }
 // A reader admitted during a paused second-family commit sees only committed
 // state after its owner lock is released, never the staged candidate.
 for(bool fail:{false,true}){
  reset();Kernel k;P p(k);C(p.start()==0&&p.replace(empty)==0);k.pause=true;if(fail)k.failWriteAt=k.writes+2;
  int writeResult=777,readResult=777;std::atomic<bool> readerStarted{false};
  std::thread writer([&]{writeResult=p.setDataSaver(true);});
  {std::unique_lock<std::mutex> lock(k.gate);k.cv.wait(lock,[&]{return k.blocked;});}
  std::thread reader([&]{readerStarted=true;readResult=p.isNetworkingBlocked(10001,true);});
  while(!readerStarted.load())std::this_thread::yield();
  {std::lock_guard<std::mutex> lock(k.gate);k.resume=true;}k.cv.notify_all();writer.join();reader.join();
  C(writeResult==(fail?-EREMOTEIO:0));C(readResult==(fail?-EAGAIN:1));C(fail?held:!held);
 }
 C(held&&files.empty());printf("passed_cases=%u\n",cases);
}
