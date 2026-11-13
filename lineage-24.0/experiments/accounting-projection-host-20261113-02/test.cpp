#include <linux/netfilter/gta3xlwifi_loopback.h>
static bool firewallAllowed=true;

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
extern "C" int imageIoctl(int fd,unsigned long cmd,...){
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
void resetLna(){resetImage();features=127;netImage.clear();hostImage.clear();lnaRevision=0;lnaIoctls=lnaGets=lnaSets=lnaFaultAt=lnaFault=lnaErrorAt=0;lnaError=lnaSetError=lnaAck=lnaEintr=0;lnaCommitError=lnaReleaseAfterSet=false;}
void seedLna(){lnaRevision=9;netImage=encode(network);hostImage=encode(host);}
LImage sentinelLna(){return {777,{entry(192,77,true)},{entry(64,88,false)}};}
bool untouchedLna(const LImage&v){auto expected=sentinelLna();return v.revision==expected.revision&&v.network==expected.network&&v.host==expected.host;}

static unsigned ioCount,ioFault;static bool ioAfter;
static bool point(){return ++ioCount==ioFault;}
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);bool bad=point();if(bad&&!ioAfter){errno=EIO;return -1;}if(cmd==GTA3XLWIFI_LOOPBACK_GET_EVENTS){errno=ENOTTY;return -1;}int result=imageIoctl(fd,cmd,arg);if(bad){errno=EIO;return -1;}return result;}
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
   assert(!output);write=true;if(line.rfind("-N ",0)==0){assert(t.chains.emplace(line.substr(3),std::vector<std::string>{}).second);}else if(line.front()==':'){auto n=line.substr(1,line.find(' ')-1);assert(t.chains.count(n));t.chains[n].clear();}else if(line.rfind("-A ",0)==0){auto n=line.substr(3,line.find(' ',3)-3);assert(t.chains.count(n));t.chains[n].push_back(line);}else assert(false);
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

#include "Gta3xlwifiSocketPolicyProjection.h"
#include <thread>
using P=SocketPolicyProjection;
struct Combined:IptablesRestoreInterface{
 Tables socket;MK filter;unsigned calls=0;bool denyControl=false;
 std::array<std::map<std::string,std::vector<std::string>>,2> hooks;
 Combined(){for(unsigned f=0;f<2;f++){filter.tables[f].chains["bw_FORWARD"]={};for(auto n:{"INPUT","FORWARD","OUTPUT"})hooks[f][n]={"-A "+std::string(n)+" -m gta3xlwifi_guard -j DROP"};}}
 int execute(IptablesTarget family,const std::string&cmd,std::string*out)override{
  assert(firewallAllowed);++calls;bool bad=point();if(bad&&!ioAfter)return -1;
  if(denyControl)for(auto&e:kernelImage)if(e.uid==0&&(e.permissions&4))return -1;
  int result=0;
  if(cmd.rfind("*g24sock\n",0)==0)result=socket.execute(family,cmd,out);
  else{
   auto f=family==V4?0:1;bool handled=false;
   for(unsigned i=0;i<3;i++){std::string n=i==0?"INPUT":i==1?"FORWARD":"OUTPUT";
    if(cmd=="*filter\n-S "+n+"\nCOMMIT\n"){assert(out);*out="-P "+n+" "+filter.tables[f].builtin[i]+"\n";for(auto&r:hooks[f][n])*out+=r+"\n";handled=true;}
   }
   if(!handled&&cmd.rfind("*filter\n-I ",0)==0){assert(!out);std::istringstream in(cmd);std::string line;std::getline(in,line);while(std::getline(in,line)&&line!="COMMIT"){auto n=line.substr(3,line.find(' ',3)-3);hooks[f][n].insert(hooks[f][n].begin(),"-A "+n+" -m gta3xlwifi_guard -j DROP");}handled=true;}
   if(!handled){result=filter.execute(family,cmd,out);if(out&&cmd=="*filter\n-S\nCOMMIT\n")for(const auto&[n,rules]:hooks[f])for(const auto&rule:rules)*out+=rule+"\n";}
  }
  return bad?-1:result;
 }
};
void resetProjection(){resetLna();features=1023;ioCount=ioFault=0;ioAfter=false;firewallAllowed=true;}
P::State desired(unsigned marker=10001){P::State s;assert(s.policy.setChainEnabled(1,true)==0&&s.policy.setUidRule(1,marker,UidPolicy::Allow)==0);s.policy.setDataSaver(true);assert(s.ingress.setIif(marker,17)==0&&s.ingress.setLockdown(marker,true)==0);assert(s.permissions.set(marker,65)==0);NetpolicyLease::LocalNetworkEntry h={64,{},true};memcpy(h.key.data(),&marker,4);assert(s.local.set(LocalNetworkState::Table::Host,h)==0);return s;}
void checkState(P&p,unsigned marker,uint64_t generation){P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==0&&g==generation);int32_t rule=0;uint32_t perm=0;C(out.policy.getUidRule(1,marker,&rule)==0&&rule==UidPolicy::Allow&&out.permissions.get(marker,&perm)==0&&perm==65);std::vector<int32_t> u;C(out.ingress.ownerUids(&u)==0&&u==std::vector<int32_t>{int32_t(marker)});std::vector<NetpolicyLease::LocalNetworkEntry> n,h;C(out.local.snapshot(&n,&h)==0&&h.size()==1);}

static const std::vector<std::string> accountingProgram={"*filter","-A bw_INPUT -j bw_global_alert","-A bw_INPUT -p esp -j RETURN","-A bw_INPUT -m mark --mark 0x100000/0x100000 -j RETURN","-A bw_INPUT -j MARK --or-mark 0x100000","-A bw_OUTPUT -j bw_global_alert","-A bw_costly_shared -j bw_penalty_box","-A bw_data_saver -j RETURN","COMMIT","*raw","-A bw_raw_PREROUTING -m mark --mark 0xdeadc1a7 -j DROP","-A bw_raw_PREROUTING -i ipsec+ -j RETURN","-A bw_raw_PREROUTING -m policy --pol ipsec --dir in -j RETURN","-A bw_raw_PREROUTING -m gta3xlwifi_iface_stats --direction ingress","COMMIT","*mangle","-A bw_mangle_POSTROUTING -o ipsec+ -j RETURN","-A bw_mangle_POSTROUTING -m policy --pol ipsec --dir out -j RETURN","-A bw_mangle_POSTROUTING -j MARK --set-mark 0x0/0x100000","-A bw_mangle_POSTROUTING -m gta3xlwifi_iface_stats --direction egress","COMMIT\n"};
static const std::vector<std::pair<std::string,std::string>> formatters={{"-j MARK --or-mark 0x100000","-j MARK --set-xmark 0x100000/0x100000"},{"-j MARK --set-mark 0x0/0x100000","-j MARK --set-xmark 0x0/0x100000"},{"-m policy --pol ipsec --dir in","-m policy --dir in --pol ipsec"},{"-m policy --pol ipsec --dir out","-m policy --dir out --pol ipsec"}};

static std::string accountingCanonical(std::string line){for(const auto&[from,to]:formatters){auto n=line.find(from);if(n!=std::string::npos)line.replace(n,from.size(),to);}return line;}
using AccountingRules=std::map<std::string,std::vector<std::string>>;
struct AccountingTable{AccountingRules chains;std::vector<std::string> policies;bool operator==(const AccountingTable&)const=default;};
using AccountingTables=std::array<std::array<AccountingTable,3>,2>;
static unsigned tableIndex(const std::string&name){if(name=="filter")return 0;if(name=="raw")return 1;assert(name=="mangle");return 2;}
static std::array<AccountingRules,3> expectedAccounting(){std::array<AccountingRules,3> rows;for(const auto*n:{"bw_INPUT","bw_OUTPUT","bw_costly_shared","bw_data_saver","bw_penalty_box","bw_happy_box"})rows[0][n]={};rows[1]["bw_raw_PREROUTING"]={};rows[2]["bw_mangle_POSTROUTING"]={};unsigned table=0;for(const auto&line:accountingProgram){if(line.front()=='*'){table=tableIndex(line.substr(1));continue;}if(line.rfind("COMMIT",0)==0)continue;auto n=line.substr(3,line.find(' ',3)-3);rows[table][n].push_back(accountingCanonical(line));}return rows;}
struct AccountingModel:IptablesRestoreInterface{
 AccountingTables tables;unsigned calls=0,writes=0,fault=0,malform=0;bool after=false,foreignMutation=false;std::string bad;
 AccountingModel(){auto rows=expectedAccounting();for(unsigned f=0;f<2;++f)for(unsigned k=0;k<3;++k){auto&t=tables[f][k];t.chains=rows[k];for(auto&[n,r]:t.chains){(void)n;r.clear();}t.chains["oem_saved"]={"-A oem_saved -m comment --comment retained -j RETURN"};if(k==0){t.chains["bw_global_alert"]={};t.policies={"-P INPUT ACCEPT","-P OUTPUT DROP","-P FORWARD DROP"};}else if(k==1)t.policies={"-P PREROUTING ACCEPT","-P OUTPUT ACCEPT"};else t.policies={"-P PREROUTING ACCEPT","-P INPUT ACCEPT","-P FORWARD ACCEPT","-P OUTPUT ACCEPT","-P POSTROUTING ACCEPT"};}}
 std::string snapshot(const AccountingTable&t){std::string s;for(const auto&line:t.policies)s+=line+"\n";for(const auto&[n,r]:t.chains){(void)r;s+="-N "+n+"\n";}for(const auto&[n,r]:t.chains){(void)n;for(const auto&line:r)s+=line+"\n";}return s;}
 int execute(IptablesTarget family,const std::string&command,std::string*output)override{
  assert(held&&files.size()==1);++calls;bool failure=calls==fault;if(failure&&!after)return -1;
  assert(family==V4||family==V6);unsigned f=family==V4?0:1;std::istringstream in(command);std::string line;assert(std::getline(in,line)&&line.front()=='*');unsigned k=tableIndex(line.substr(1));auto&t=tables[f][k];assert(std::getline(in,line));
  if(line=="-S"){assert(output&&std::getline(in,line)&&line=="COMMIT"&&!std::getline(in,line));*output=calls==malform?bad:snapshot(t);}
  else{assert(!output);++writes;do{if(line=="COMMIT")break;assert(std::find(accountingProgram.begin(),accountingProgram.end(),line)!=accountingProgram.end()&&line.rfind("-A ",0)==0);auto n=line.substr(3,line.find(' ',3)-3);assert(t.chains.count(n));t.chains[n].push_back(accountingCanonical(line));}while(std::getline(in,line));assert(line=="COMMIT"&&!std::getline(in,line));if(foreignMutation){t.chains["oem_saved"].push_back("-A oem_saved -j RETURN");foreignMutation=false;}}
  return failure?-1:0;
 }
 void assertComplete(const AccountingTables&before){auto rows=expectedAccounting();for(unsigned f=0;f<2;++f)for(unsigned k=0;k<3;++k){const auto&t=tables[f][k];assert(t.policies==before[f][k].policies);for(const auto&[n,r]:rows[k])assert(t.chains.at(n)==r);for(const auto&[n,r]:before[f][k].chains)if(!rows[k].count(n))assert(t.chains.at(n)==r);}}
};


struct AccountingCombined:Combined{
 AccountingModel accounting;
 AccountingCombined(){for(unsigned f=0;f<2;++f)for(const auto&[n,r]:accounting.tables[f][0].chains)filter.tables[f].chains[n]=r;}
 int execute(IptablesTarget family,const std::string&command,std::string*out)override{
  if(command.rfind("*raw\n",0)==0||command.rfind("*mangle\n",0)==0){assert(firewallAllowed);++calls;bool bad=point();if(bad&&!ioAfter)return -1;int result=accounting.execute(family,command,out);return bad?-1:result;}
  return Combined::execute(family,accountingCanonical(command),out);
 }
};
static void resetIntegrated(){resetProjection();features=4095;}
int main(){unsigned startPoints=0,replacePoints=0;
 auto state=desired();auto other=desired(110001);auto invalid=accountingProgram;invalid.push_back("*filter");
 resetIntegrated();{AccountingCombined k;P p(k);C(p.startWithAccounting(invalid)==-EINVAL&&opens==0&&ioCount==0);C(p.startWithAccounting(accountingProgram)==0&&held&&opens==1);startPoints=ioCount;P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);ioCount=0;C(p.replace(state,0)==0&&!held&&opens==1&&files.size()==1);replacePoints=ioCount;checkState(p,10001,1);auto before=ioCount;C(p.startWithAccounting(accountingProgram)==-EALREADY&&ioCount==before&&!held);C(p.setDataSaver(false)==0&&!held);C(p.snapshot(&out,&g)==0&&g==2&&!out.policy.dataSaver());
  k.filter.tables[0].chains["bw_INPUT"].insert(k.filter.tables[0].chains["bw_INPUT"].begin(),"-A bw_INPUT -i wlan0 -j bw_costly_shared");auto quota=k.filter.tables[0].chains["bw_INPUT"];C(p.setDataSaver(true)==0&&k.filter.tables[0].chains["bw_INPUT"]==quota&&!held);
  k.accounting.tables[1][2].chains["bw_mangle_POSTROUTING"].pop_back();C(p.setDataSaver(false)==-EPROTO&&held&&files.empty());C(p.snapshot(&out,&g)==-EAGAIN);
 }
 for(unsigned bit=0;bit<12;++bit){resetIntegrated();features=4095^(1u<<bit);AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==-EOPNOTSUPP&&held&&files.empty()&&k.calls==0);}
 for(bool after:{false,true})for(unsigned point=1;point<=startPoints;++point){resetIntegrated();AccountingCombined k;P p(k);ioFault=point;ioAfter=after;C(p.startWithAccounting(accountingProgram)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 for(bool after:{false,true})for(unsigned point=1;point<=replacePoints;++point){resetIntegrated();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);ioCount=0;ioFault=point;ioAfter=after;C(p.replace(state,0)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.replace(other,0)==-ENOTCONN);}
 resetIntegrated();{AccountingCombined k;for(auto&f:k.hooks)for(auto&[n,r]:f){(void)n;r.clear();}P p(k);C(p.startWithAccounting(accountingProgram,P::HookMode::InstallMissing)==0&&held);C(p.replace(state,0)==0&&!held&&opens==1);}
 for(unsigned point:{startPoints/2,startPoints-2}){resetIntegrated();AccountingCombined k;P p(k);ioFault=point;ioAfter=true;C(p.startWithAccounting(accountingProgram)<0&&held&&files.empty());ioFault=0;C(p.startWithAccounting(accountingProgram)==0&&held);C(p.replace(state,0)==0&&!held);}
 resetIntegrated();{AccountingCombined k;k.accounting.tables[1][2].chains["bw_mangle_POSTROUTING"]={"-A bw_mangle_POSTROUTING -m bpf --object-pinned /old"};P p(k);C(p.startWithAccounting(accountingProgram)==-EPROTO&&k.filter.writes==0&&k.accounting.writes==0&&held&&files.empty());}
 C(files.empty()&&held);printf("passed_cases=%u start_fault_points=%u replace_fault_points=%u\n",cases,startPoints,replacePoints);
}
