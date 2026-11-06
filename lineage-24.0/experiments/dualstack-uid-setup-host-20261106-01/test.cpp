
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
  assert(f==V4||f==V6);assert(held&&opens==1);++calls;
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
 reset();{Kernel k;D d(k);C(d.replace(image(110001),image(110001))==-ENOTCONN&&k.calls==0);C(d.start()==0&&held);C(d.start()==-EALREADY&&k.calls==6);C(d.replace(image(110001),image(110001))==0&&!held&&k.uid[V4]==110001&&k.uid[V6]==110001);C(d.replace(image(110001),image(110001))==0&&!held&&k.writes==2);d.stop();C(held&&opens==0);d.stop();C(closes==1);}
 for(int f:{int(V4),int(V6)})for(auto chain:{"INPUT","FORWARD","OUTPUT"}){
  reset();Kernel k;k.badFamily=f;k.badChain=chain;k.overrideText="-P "+std::string(chain)+" ACCEPT\n";D d(k);C(d.start()==-EPROTO&&held&&files.empty()&&k.writes==0);C(d.replace(image(110001),image(110001))==-ENOTCONN);
 }
 for(auto bad:std::vector<std::string>{"","-P INPUT ACCEPT\n-A INPUT -j ACCEPT\n-A INPUT -m gta3xlwifi_guard -j DROP\n","-P INPUT ACCEPT\n-A INPUT -m gta3xlwifi_guard -j RETURN\n","-P INPUT ACCEPT\n-A INPUT -o lo -m gta3xlwifi_guard -j DROP\n","-P INPUT ACCEPT\n-A INPUT -m gta3xlwifi_guard -j DROP","-P INPUT ACCEPT\r\n-A INPUT -m gta3xlwifi_guard -j DROP\n","-P INPUT ACCEPT\n-A INPUT -m gta3xlwifi_guard -j DROP\n-N foreign\n",std::string(1024*1024+1,'x')}){
  reset();Kernel k;k.badFamily=V4;k.badChain="INPUT";k.overrideText=bad;D d(k);C(d.start()==-EPROTO&&held&&files.empty());
 }
 reset();{Kernel k;k.badFamily=V4;k.badChain="INPUT";k.overrideText="-P INPUT DROP\n-A INPUT -m gta3xlwifi_guard -j DROP\n";D d(k);C(d.start()==0&&held);}
 reset();abi=2;{Kernel k;D d(k);C(d.start()==-EPROTO&&k.calls==0&&held&&files.empty());}
 for(auto failure:{1u,2u})for(bool committed:{false,true}){
  reset();Kernel k;D d(k);C(d.start()==0);k.failWriteAt=failure;k.commitFailure=committed;C(d.replace(image(110001),image(110001))==-EREMOTEIO&&held&&k.uid[V4]==10001&&k.uid[V6]==10001);k.failWriteAt=0;C(d.replace(image(120001),image(120001))==0&&!held&&k.uid[V4]==120001&&k.uid[V6]==120001);
 }
 reset();{Kernel k;D d(k);C(d.start()==0&&d.replace(image(110001),image(110001))==0);k.writes=0;k.failWriteAt=2;C(d.replace(image(120001),image(120001))==-EREMOTEIO&&!held&&k.uid[V4]==110001&&k.uid[V6]==110001);}
 reset();{Kernel k;D d(k);C(d.start()==0);k.failAfter=2;C(d.replace(image(110001),image(110001))==-EUCLEAN&&held&&files.empty());auto calls=k.calls;C(d.replace(image(120001),image(120001))==-ENOTCONN&&k.calls==calls);}
 reset();{Kernel k;D d(k);C(d.start()==0);k.badUidReadAt=1;C(d.replace(image(110001),image(110001))==-EPROTO&&held&&files.empty()&&k.writes==0);}
 reset();{Kernel k;D d(k);C(d.start()==0);k.badUidReadAt=7;C(d.replace(image(110001),image(110001))==-EPROTO&&held&&k.uid[V4]==10001&&k.uid[V6]==10001);}
 reset();{Kernel k;D d(k);C(d.start()==0);k.changeHooksOnWrite=true;C(d.replace(image(110001),image(110001))==-EUCLEAN&&held&&files.empty());}
 reset();{Kernel k;D d(k);C(d.start()==0);ioctlError=EIO;errorCommand=GTA3XLWIFI_NETPOLICY_RELEASE;commitError=true;C(d.replace(image(110001),image(110001))==-EUCLEAN&&held&&files.empty());auto calls=k.calls;C(d.replace(image(120001),image(120001))==-ENOTCONN&&k.calls==calls);}
 reset();{Kernel k;D d(k);C(d.start()==0);ioctlError=EPERM;errorCommand=GTA3XLWIFI_NETPOLICY_HOLD;C(d.replace(image(110001),image(110001))==-EPERM&&held&&files.empty()&&k.writes==0);}
 reset();{Kernel k;D d(k);C(d.start()==0);auto invalid=image(110001);invalid[0].name="foreign";C(d.replace(invalid,image(110001))==-EINVAL&&held&&files.empty()&&k.writes==0);}
 reset();{Kernel k;D d(k);C(d.start()==0);auto invalid=image(110001);invalid[0].rules[0].uid=Chains::UidRange{20,10};C(d.replace(image(110001),invalid)==-EINVAL&&held&&k.uid[V4]==10001&&k.uid[V6]==10001);}
 using Mode=D::HookMode;
 reset();{Kernel k;k.missing();D d(k);C(d.start(Mode::InstallMissing)==0&&held&&k.writes==2);for(auto f:{V4,V6})for(auto c:{"INPUT","FORWARD","OUTPUT"})C(k.guards[{f,c}]);C(d.replace(image(110001),image(110001))==0&&!held);}
 reset();{Kernel k;D d(k);C(d.start(Mode::InstallMissing)==0&&held&&k.writes==0);}
 reset();{Kernel k;k.guards[{V6,"OUTPUT"}]=false;D d(k);C(d.start(Mode::InstallMissing)==0&&held&&k.writes==1);}
 for(auto failure:{1u,2u})for(bool committed:{false,true}){
  reset();Kernel k;k.missing();k.failWriteAt=failure;k.commitFailure=committed;D d(k);C(d.start(Mode::InstallMissing)==-EREMOTEIO&&held&&files.empty());C(d.replace(image(110001),image(110001))==-ENOTCONN);k.failWriteAt=0;C(d.start(Mode::InstallMissing)==0&&held);C(d.replace(image(120001),image(120001))==0&&!held);
 }
 reset();{Kernel k;k.missing();k.badFamily=V6;k.badChain="OUTPUT";k.overrideText="-P OUTPUT ACCEPT\n-A OUTPUT -j ACCEPT\n-A OUTPUT -m gta3xlwifi_guard -j DROP\n";D d(k);C(d.start(Mode::InstallMissing)==-EPROTO&&held&&files.empty()&&k.writes==0);}
 reset();{Kernel k;D d(k);C(d.start(static_cast<Mode>(9))==-EINVAL&&held&&files.empty()&&k.calls==0);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
