
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

#include "Gta3xlwifiSocketRoots.h"
#include "Gta3xlwifiOrdinaryDispatch.h"
#include <sstream>
#include <map>
#include <array>
using namespace android::net::gta3xlwifi;
using ChainIO=CheckedUidChains;using RootImage=SocketRoots::Image;
std::vector<std::string> allNames(){std::vector<std::string> n;for(int i=1;i<=9;i++)n.push_back("g24_uid_"+std::to_string(i));n.push_back("g24_owner_in");n.push_back("g24_owner_out");return n;}
RootImage program(){UidPolicy p;assert(p.setChainEnabled(1,true)==0&&p.setUidRule(1,10001,UidPolicy::Allow)==0);RootImage v;assert(UidChainProgram::ordinary(p,&v)==0&&OrdinaryDispatch::append(&v)==0);return v;}
std::string ruleText(const ChainIO::Chain&c,const ChainIO::Rule&r){
 using X=ChainIO;std::string s="-A "+c.name;
 if(r.selector==X::Selector::OwnerSkip)s+=" -m gta3xlwifi_owner_skip";
 else if(r.selector==X::Selector::NonLoopback)s+=" -m gta3xlwifi_non_loopback";
 else if(r.uid){assert(r.selector==X::Selector::RawUid||r.selector==X::Selector::RawAppId);s+=r.selector==X::Selector::RawUid?" -m gta3xlwifi_raw_uid --raw_uid ":" -m gta3xlwifi_raw_appid --raw_appid ";s+=std::to_string(r.uid->first)+":"+std::to_string(r.uid->last);}
 if(r.verdict==X::Verdict::Return)s+=" -j RETURN";
 else if(r.verdict==X::Verdict::Drop)s+=" -j DROP";
 else{assert(r.verdict==X::Verdict::UidCall);s+=" -j g24_uid_"+std::to_string(r.targetUidChain);}return s;
}
struct Tables:IptablesRestoreInterface{
 struct Table{std::array<std::string,2> policy={"DROP","DROP"};std::array<std::vector<std::string>,2> root;std::map<std::string,std::vector<std::string>> chains;};
 std::array<Table,2> state;unsigned calls=0,writes=0,failAt=0,malformAt=0,mutateAt=0;bool after=false;
 std::string malformed;std::vector<std::pair<IptablesTarget,std::string>> commands;
 void seed(const RootImage&v){for(auto&t:state)for(auto&c:v){auto&dst=t.chains[c.name];for(auto&r:c.rules)dst.push_back(ruleText(c,r));}}
 std::string listing(const Table&t){std::string s="-P INPUT "+t.policy[0]+"\n-P OUTPUT "+t.policy[1]+"\n";for(auto&[name,rules]:t.chains)s+="-N "+name+"\n";for(unsigned i=0;i<2;i++)for(auto&r:t.root[i])s+=r+"\n";for(auto&[name,rules]:t.chains)for(auto&r:rules)s+=r+"\n";return s;}
 int execute(IptablesTarget f,const std::string&command,std::string*output)override{
  assert(f==V4||f==V6);assert(!files.empty()&&held);++calls;commands.emplace_back(f,command);
  if(calls==failAt&&!after)return -1;
  auto&t=state[f==V4?0:1];std::istringstream in(command);std::string line;assert(std::getline(in,line)&&line=="*g24sock");std::string text;bool write=false;
  while(std::getline(in,line)){
   if(line=="COMMIT")break;
   if(line=="-S"){assert(output);text+=listing(t);continue;}
   if(line.rfind("-S ",0)==0){assert(output);auto name=line.substr(3);assert(t.chains.count(name));text+="-N "+name+"\n";for(auto&r:t.chains.at(name))text+=r+"\n";continue;}
   assert(!output);write=true;
   if(line.rfind("-N ",0)==0){assert(t.chains.emplace(line.substr(3),std::vector<std::string>{}).second);}
   else if(line.rfind("-A INPUT ",0)==0)t.root[0].push_back(line);
   else if(line.rfind("-A OUTPUT ",0)==0)t.root[1].push_back(line);
   else if(line=="-P INPUT ACCEPT")t.policy[0]="ACCEPT";
   else if(line=="-P OUTPUT ACCEPT")t.policy[1]="ACCEPT";
   else assert(false);
  }
  if(write)++writes;
  if(calls==mutateAt){t.policy[0]="ACCEPT";t.root[0]={"-A INPUT -j g24_owner_in"};}
  if(output)*output=calls==malformAt?malformed:text;
  if(calls==failAt)return -1;
  return 0;
 }
 bool active(){for(auto&t:state)if(t.policy!=std::array<std::string,2>{"ACCEPT","ACCEPT"}||t.root[0]!=std::vector<std::string>{"-A INPUT -j g24_owner_in"}||t.root[1]!=std::vector<std::string>{"-A OUTPUT -j g24_owner_out"})return false;return true;}
};
void initRoots(){resetImage();features=511;}
int main(){
 auto wanted=program();
 initRoots();{NetpolicyLease l;C(l.requireSocketTables()==-ENOTCONN);C(l.start()==0);ioctlEintr=2;C(l.requireSocketTables()==0&&ioctlEintr==0&&held);}
 for(int f:{0,7,127,255}){initRoots();features=f;NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==-EOPNOTSUPP&&files.empty()&&held&&k.calls==0);}
 for(int e:{ENOTTY,EIO,EACCES}){initRoots();NetpolicyLease l;C(l.start()==0);ioctlError=e;errorCommand=GTA3XLWIFI_UID_FEATURES;C(l.requireSocketTables()==-e&&files.empty()&&held);}
 unsigned prepareCalls=0,activateCalls=0;
 initRoots();{NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==0&&held&&!files.empty()&&k.writes==2&&!k.active());prepareCalls=k.calls;C(roots.prepare()==0&&k.writes==2&&held);k.seed(wanted);unsigned before=k.calls;C(roots.activate(wanted)==0&&held&&k.active()&&k.writes==4);activateCalls=k.calls-before;C(roots.verify(wanted)==0&&held);C(roots.activate(wanted)==0&&k.writes==4);C(roots.prepare()==0&&k.writes==4&&k.active());}
 // Every I/O point: failure before or after a possible commit keeps the lease
 // closed/held; an explicit new lease can recover only valid partial state.
 for(bool committed:{false,true})for(unsigned point=1;point<=prepareCalls;point++){
  initRoots();NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0);k.failAt=point;k.after=committed;C(roots.prepare()<0&&held&&files.empty());k.failAt=0;C(l.start()==0&&roots.prepare()==0&&held&&k.writes<=3);
 }
 for(bool committed:{false,true})for(unsigned point=1;point<=activateCalls;point++){
  initRoots();NetpolicyLease l;Tables k;k.seed(wanted);SocketRoots roots(k,l);C(l.start()==0);k.failAt=point;k.after=committed;C(roots.activate(wanted)<0&&held&&files.empty());k.failAt=0;C(l.start()==0&&roots.activate(wanted)==0&&held&&k.active());
 }
 // Both family inventories must pass before the first modification.
 for(unsigned f:{0u,1u})for(int fault=0;fault<12;fault++){
  initRoots();NetpolicyLease l;Tables k;auto&t=k.state[f];
  switch(fault){case 0:t.policy[0]="ACCEPT";break;case 1:t.policy[1]="ACCEPT";break;case 2:t.chains["foreign"]={};break;case 3:t.root[0]={"-A INPUT -j ACCEPT"};break;case 4:t.root[1]={"-A OUTPUT -j g24_owner_in"};break;case 5:t.chains["g24_owner_in"]={};t.root[0]={"-A INPUT -j g24_owner_in","-A INPUT -j g24_owner_in"};break;case 6:t.chains["g24_uid_1"]={"-A g24_uid_1 -j DROP"};break;case 7:t.policy[0]="QUEUE";break;case 8:t.chains["g24_uid_10"]={};break;case 9:t.root[0]={"-A INPUT -j g24_owner_in"};break;case 10:t.chains["g24_uid_1"]={"-A g24_uid_1 -j NFQUEUE"};break;case 11:t.chains["g24_owner_in"]={};t.root[0]={"-A INPUT -j g24_owner_in"};break;}
  SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==-EPROTO&&k.writes==0&&files.empty()&&held);
 }
 for(auto bad:std::vector<std::string>{"", "-P INPUT DROP\n", "-P INPUT DROP\n-P INPUT DROP\n-P OUTPUT DROP\n", "-P INPUT DROP\n-P OUTPUT DROP", "-P INPUT DROP\n-P OUTPUT DROP\n-P FORWARD DROP\n", "-P INPUT DROP\n-P OUTPUT DROP\n\n", std::string("-P INPUT DROP\n-P OUTPUT DROP\n\0",29),"-P INPUT DROP\n-P OUTPUT DROP\n# arbitrary\n",std::string(1024*1024+1,'x')+"\n"}){
  initRoots();NetpolicyLease l;Tables k;k.malformAt=1;k.malformed=bad;SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==-EPROTO&&held&&files.empty()&&k.writes==0);
 }
 // Malformed owned rules and drift are rejected without root activation.
 for(unsigned f:{0u,1u}){
  initRoots();NetpolicyLease l;Tables k;k.seed(wanted);k.state[f].chains["g24_uid_1"].push_back("-A g24_uid_1 -j NFQUEUE");SocketRoots roots(k,l);C(l.start()==0&&roots.activate(wanted)==-EPROTO&&k.writes==0&&held&&files.empty());
  initRoots();NetpolicyLease q;Tables changed;changed.seed(wanted);changed.state[f].chains["g24_uid_1"]={"-A g24_uid_1 -j DROP"};SocketRoots other(changed,q);C(q.start()==0&&other.activate(wanted)==-ESTALE&&held&&files.empty()&&changed.writes==0);
 }
 initRoots();{NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0&&l.release()==0);C(roots.prepare()==-EBUSY&&held&&files.empty()&&k.calls==0);}
 initRoots();{NetpolicyLease l;Tables k;SocketRoots roots(k,l);C(l.start()==0);for(int fault=0;fault<5;fault++){auto bad=wanted;if(fault==0)bad.pop_back();if(fault==1)std::swap(bad[0],bad[1]);if(fault==2)bad.back().rules.clear();if(fault==3)bad[0].rules.push_back({std::nullopt,ChainIO::Verdict::Reject});if(fault==4)bad[9].rules[0].uid=ChainIO::UidRange{0,10000};C(roots.activate(bad)==-EINVAL&&k.calls==0&&!files.empty()&&held);C(roots.verify(bad)==-EINVAL&&k.calls==0&&!files.empty());}}
 // Fresh chain creation must not silently enable a root during readback.
 initRoots();{NetpolicyLease l;Tables k;k.mutateAt=4;SocketRoots roots(k,l);C(l.start()==0&&roots.prepare()==-EPROTO&&held&&files.empty());}
 // A valid half-activated family is recoverable under a new held lease.
 initRoots();{NetpolicyLease l;Tables k;k.seed(wanted);k.state[0].root[0]={"-A INPUT -j g24_owner_in"};k.state[0].policy[0]="ACCEPT";SocketRoots roots(k,l);C(l.start()==0&&roots.activate(wanted)==0&&held&&k.active());}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
