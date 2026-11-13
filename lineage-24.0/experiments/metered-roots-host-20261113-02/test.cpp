
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
 if(r.ingressIfIndex)s+=" -m gta3xlwifi_bad_iif --allowed-iif "+std::to_string(*r.ingressIfIndex);
 if(r.ingressDiscard){const auto&d=*r.ingressDiscard;s+=" -m gta3xlwifi_ingress_discard --ingress-daddr ";for(unsigned char b:d.daddr){char h[3];snprintf(h,3,"%02x",b);s+=h;}s+=" --allowed-iif1 "+std::to_string(d.allowedIfIndex[0])+" --allowed-iif2 "+std::to_string(d.allowedIfIndex[1]);}
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
   else if(line.front()==':'){auto name=line.substr(1,line.find(' ')-1);assert(t.chains.count(name));t.chains[name].clear();}
   else if(line.rfind("-A ",0)==0){auto name=line.substr(3,line.find(' ',3)-3);assert(t.chains.count(name));t.chains[name].push_back(line);}
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

#include "Gta3xlwifiIngressPolicy.h"
extern "C" int g24OracleChecks();extern "C" int g24OracleIif(uint32_t,uint32_t,uint32_t,int,int);extern "C" int g24OracleDiscard(const uint8_t*,const uint8_t*,uint32_t,uint32_t,uint32_t,int,unsigned);
using IP=IngressPolicy;
RootImage ordinary(){UidPolicy policy;RootImage image;assert(UidChainProgram::ordinary(policy,&image)==0&&OrdinaryDispatch::append(&image)==0);return image;}
IP::Address address(unsigned n){IP::Address a{};a[0]=0x20;a[1]=1;a[14]=n>>8;a[15]=n;return a;}
bool evaluate(const RootImage&v,uint32_t uid,uint32_t iif,bool dns,bool output,const IP::Address&dst,unsigned version=6){
 if(output||iif==1)return false;
 for(auto&r:v[9].rules){
  if(r.ingressDiscard&&version&&dst==r.ingressDiscard->daddr&&iif!=r.ingressDiscard->allowedIfIndex[0]&&iif!=r.ingressDiscard->allowedIfIndex[1])return true;
  if(r.ingressIfIndex&&!dns&&r.uid->first<=uid&&uid<=r.uid->last&&(!*r.ingressIfIndex||*r.ingressIfIndex!=iif))return true;
 }return false;
}

#include "Gta3xlwifiMeteredRoots.h"
#include "Gta3xlwifiMeteredChainProgram.h"
using MR=MeteredRoots;
const std::vector<std::string> meterNames={"g24_meter_deny","g24_meter_allow","g24_data_saver"};
RootImage metered(bool saver=false,bool happy=false,bool deny=false,uint32_t uid=10001){UidPolicy p;p.setDataSaver(saver);if(happy)assert(p.setUidRule(10,uid,UidPolicy::Allow)==0);if(deny)assert(p.setUidRule(11,uid,UidPolicy::Deny)==0);RootImage v;assert(MeteredChainProgram::compile(p,&v)==0);return v;}
struct MK:IptablesRestoreInterface{
 struct T{std::map<std::string,std::vector<std::string>> chains;std::array<std::string,3> builtin={"ACCEPT","DROP","ACCEPT"};};std::array<T,2> tables;
 unsigned calls=0,writes=0,failAt=0,malformAt=0,foreignAt=0;bool after=false;std::string malformed;
 MK(){for(auto&t:tables){for(const auto&n:{"bw_penalty_box","bw_happy_box","bw_data_saver","bw_INPUT","bw_OUTPUT","bw_costly_test","foreign"})t.chains[n]={};t.chains["bw_data_saver"]={"-A bw_data_saver -j RETURN"};t.chains["bw_costly_test"]={"-A bw_costly_test -m quota2 --name quota_test --quota 100000 -j REJECT","-A bw_costly_test -j bw_penalty_box"};t.chains["bw_INPUT"]={"-A bw_INPUT -i wlan0 -j bw_costly_test"};t.chains["bw_OUTPUT"]={"-A bw_OUTPUT -o wlan0 -j bw_costly_test"};}}
 void seed(const RootImage&v){for(auto&t:tables)for(const auto&c:v){auto&dst=t.chains[c.name];for(const auto&r:c.rules){std::string line="-A "+c.name;if(r.uid){line+=r.selector==ChainIO::Selector::RawAppId?" -m gta3xlwifi_raw_appid --raw_appid ":" -m gta3xlwifi_raw_uid --raw_uid ";line+=std::to_string(r.uid->first)+":"+std::to_string(r.uid->last);}if(r.verdict==ChainIO::Verdict::DataSaverGoto)line+=" -g g24_data_saver";else line+=r.verdict==ChainIO::Verdict::Reject?" -j REJECT":" -j RETURN";dst.push_back(line);}}}
 std::string list(const T&t,IptablesTarget family,const std::string&n){assert(t.chains.count(n));std::string out="-N "+n+"\n";for(auto line:t.chains.at(n)){if(line.ends_with(" -j REJECT"))line+=family==V4?" --reject-with icmp-port-unreachable":" --reject-with icmp6-port-unreachable";out+=line+"\n";}return out;}
 int execute(IptablesTarget family,const std::string&command,std::string*output)override{
  assert((family==V4||family==V6)&&held&&!files.empty());++calls;if(calls==failAt&&!after)return -1;auto&t=tables[family==V4?0:1];std::istringstream in(command);std::string line,text;assert(std::getline(in,line)&&line=="*filter");bool write=false;
  while(std::getline(in,line)){if(line=="COMMIT")break;if(line=="-S"){assert(output);unsigned i=0;for(auto n:{"INPUT","FORWARD","OUTPUT"})text+="-P "+std::string(n)+" "+t.builtin[i++]+"\n";for(auto&[n,r]:t.chains)text+="-N "+n+"\n";for(auto&[n,r]:t.chains){auto s=list(t,family,n);text+=s.substr(s.find('\n')+1);}continue;}
   if(line.rfind("-S ",0)==0){assert(output);text+=list(t,family,line.substr(3));continue;}
   assert(!output);write=true;if(line.rfind("-N ",0)==0){assert(t.chains.emplace(line.substr(3),std::vector<std::string>{}).second);}else if(line.rfind("-A ",0)==0){auto n=line.substr(3,line.find(' ',3)-3);assert(t.chains.count(n));t.chains[n].push_back(line);}else assert(false);
  }if(write)++writes;if(calls==foreignAt)t.chains["foreign"].push_back("-A foreign -j RETURN");if(output)*output=calls==malformAt?malformed:text;return calls==failAt?-1:0;
 }
};
// Execute actual newly emitted goto/call graph. Quota and raw UID/appId effects
// are fixtures; comparison below uses the independent original A17 rule order.
int runChain(const MK::T&t,const std::string&name,uint32_t uid,unsigned type,bool v6,bool quota,unsigned depth=0){assert(depth<12);for(const auto&line:t.chains.at(name)){
 std::istringstream in(line);std::vector<std::string>w;for(std::string x;in>>x;)w.push_back(x);bool match=true;
 for(size_t i=2;i+1<w.size();i++){if(w[i]=="--raw_uid"||w[i]=="--raw_appid"){auto r=w[++i];auto sep=r.find(':');unsigned a=std::stoul(r.substr(0,sep)),b=std::stoul(r.substr(sep+1));unsigned actual=uid;if(w[i-1]=="--raw_appid")actual=(uid==65534?0:uid)%100000;match&=a<=actual&&actual<=b;}else if(w[i]=="--icmpv6-type"){match&=v6&&type==std::stoul(w[++i]);}else if(w[i]=="--quota"){++i;match&=quota;}}
 if(!match){continue;}
 auto target=w.back();bool go=w[w.size()-2]=="-g";if(target=="RETURN")return 0;if(target=="REJECT")return 1;int child=runChain(t,target,uid,type,v6,quota,depth+1);if(child||go)return child;
 }return 0;
}
int main(){unsigned prepareCalls=0,activateCalls=0,comparisons=0;auto desired=metered(true);
 initRoots();{NetpolicyLease l;MK k;MR roots(k,l);C(l.start()==0&&roots.prepare()==0&&held&&k.writes==2);prepareCalls=k.calls;C(roots.prepare()==0&&k.writes==2);k.seed(desired);auto foreign=k.tables[0].chains["bw_costly_test"];unsigned before=k.calls;C(roots.activate(desired)==0&&held&&k.writes==4);activateCalls=k.calls-before;C(roots.verify(desired)==0&&roots.verifyPrepared()==0);C(k.tables[0].chains["bw_costly_test"]==foreign&&k.tables[0].builtin[1]=="DROP");C(roots.activate(desired)==0&&k.writes==4);C(k.tables[1].chains["bw_happy_box"].size()==7);}
 for(bool committed:{false,true})for(unsigned point=1;point<=prepareCalls;point++){initRoots();NetpolicyLease l;MK k;MR roots(k,l);C(l.start()==0);k.failAt=point;k.after=committed;C(roots.prepare()<0&&held&&files.empty());k.failAt=0;C(l.start()==0&&roots.prepare()==0&&held);}
 for(bool committed:{false,true})for(unsigned point=1;point<=activateCalls;point++){initRoots();NetpolicyLease l;MK k;k.seed(desired);MR roots(k,l);C(l.start()==0);k.failAt=point;k.after=committed;C(roots.activate(desired)<0&&held&&files.empty());k.failAt=0;C(l.start()==0&&roots.activate(desired)==0&&held);}
 for(unsigned f=0;f<2;f++)for(unsigned fault=0;fault<7;fault++){initRoots();NetpolicyLease l;MK k;auto&t=k.tables[f];if(fault==0)t.chains["bw_penalty_box"]={"-A bw_penalty_box -m bpf --object-pinned /sys/fs/bpf/netd_shared/prog_netd_denylist_xtbpf -j REJECT"};if(fault==1)t.chains["bw_happy_box"]={"-A bw_happy_box -j bw_data_saver"};if(fault==2)t.chains["g24_owner_in"]={};if(fault==3)t.chains["foreign"]={"-A foreign -j g24_meter_allow"};if(fault==4)t.chains.erase("bw_penalty_box");if(fault==5)t.chains["g24_meter_deny"]={"-A g24_meter_deny -j RETURN"};if(fault==6)t.chains["bw_penalty_box"]={"-A bw_penalty_box -j bw_happy_box"};MR roots(k,l);C(l.start()==0&&roots.prepare()==-EPROTO&&held&&files.empty()&&k.writes==0);}
 initRoots();{NetpolicyLease l;MK k;k.foreignAt=4;MR roots(k,l);C(l.start()==0&&roots.prepare()==-ESTALE&&files.empty()&&held);}
 initRoots();{NetpolicyLease l;MK k;MR roots(k,l);C(l.start()==0&&l.release()==0);C(roots.prepare()==-EBUSY&&files.empty()&&held&&k.calls==0);}
 for(unsigned fault=0;fault<4;fault++){auto bad=desired;if(fault==0)bad.pop_back();if(fault==1)bad[0].rules.back().verdict=ChainIO::Verdict::Reject;if(fault==2)bad[1].rules.front().uid=ChainIO::UidRange{0,10000};if(fault==3)bad[2].rules.push_back(bad[2].rules.front());initRoots();NetpolicyLease l;MK k;MR roots(k,l);C(l.start()==0);C(roots.activate(bad)==-EINVAL&&k.calls==0&&!files.empty()&&held);}
 for(bool saver:{false,true})for(bool happy:{false,true})for(bool deny:{false,true})for(uint32_t uid:{0u,1000u,10001u,65534u,110001u}){
  auto v=metered(saver,happy,deny,uid);initRoots();NetpolicyLease l;MK k;k.seed(v);MR roots(k,l);assert(l.start()==0&&roots.activate(v)==0);
  for(bool v6:{false,true})for(unsigned type:{0u,2u,128u,133u,134u,135u,136u,137u})for(bool quota:{false,true}){auto&t=k.tables[v6?1:0];bool critical=v6&&(type==2||type==133||type==134||type==135||type==136||type==137);bool allow=uid==65534||uid%100000<10000||happy;bool original=quota||deny||(!allow&&saver&&!critical);assert(bool(runChain(t,"bw_costly_test",uid,type,v6,quota))==original);++comparisons;}
 }
 C(files.empty()&&held);printf("passed_cases=%u graph_comparisons=%u\n",cases,comparisons);
}
