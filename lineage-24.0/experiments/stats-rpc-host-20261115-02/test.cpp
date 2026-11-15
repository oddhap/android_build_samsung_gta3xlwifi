static bool allowHeldActive=false;
static void resetRuntimeFixture();
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
extern "C" int underlyingOpen(const char* path,int flags,...){
 assert(flags&O_NOFOLLOW);assert(flags&O_CLOEXEC);assert((flags&O_ACCMODE)==O_RDONLY);
 assert(path==node||path==identity);
 if(openEintr){--openEintr;errno=EINTR;return -1;}
 if(openError){errno=openError;return -1;}
 if(path==node){assert(opens==0);++opens;held=true;}
 int fd=nextfd++;files.emplace(fd,Entry{path,0});return fd;
}
extern "C" int underlyingClose(int fd){
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
 if(!(t->version==1&&t->count<=65536&&bool(t->count)==bool(t->entries))){fprintf(stderr,"bad UID payload cmd=%lx version=%u count=%u ptr=%llu\n",cmd,t->version,t->count,(unsigned long long)t->entries);}assert(t->version==1&&t->count<=65536&&bool(t->count)==bool(t->entries));
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
extern "C" int ownerBaseIoctl(int fd,unsigned long cmd,...){va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);bool bad=point();if(bad&&!ioAfter){errno=EIO;return -1;}if(cmd==GTA3XLWIFI_LOOPBACK_GET_EVENTS){errno=ENOTTY;return -1;}int result=imageIoctl(fd,cmd,arg);if(bad){errno=EIO;return -1;}return result;}
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
void resetProjection(){resetLna();features=17407;ioCount=ioFault=0;ioAfter=false;firewallAllowed=true;resetRuntimeFixture();}
P::State desired(unsigned marker=10001){P::State s;s.runtime={true,7,{}};assert(s.policy.setChainEnabled(1,true)==0&&s.policy.setUidRule(1,marker,UidPolicy::Allow)==0);s.policy.setDataSaver(true);assert(s.ingress.setIif(marker,17)==0&&s.ingress.setLockdown(marker,true)==0);assert(s.permissions.set(marker,65)==0);NetpolicyLease::LocalNetworkEntry h={64,{},true};memcpy(h.key.data(),&marker,4);assert(s.local.set(LocalNetworkState::Table::Host,h)==0);return s;}
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
 AccountingModel accounting;bool driftOnPolicyWrite=false;
 AccountingCombined(){for(unsigned f=0;f<2;++f)for(const auto&[n,r]:accounting.tables[f][0].chains)filter.tables[f].chains[n]=r;}
 int execute(IptablesTarget family,const std::string&command,std::string*out)override{
  if(command.rfind("*raw\n",0)==0||command.rfind("*mangle\n",0)==0){assert(firewallAllowed);++calls;bool bad=point();if(bad&&!ioAfter)return -1;int result=accounting.execute(family,command,out);return bad?-1:result;}
  int result=Combined::execute(family,accountingCanonical(command),out);
  if(driftOnPolicyWrite&&command.rfind("*g24sock\n:",0)==0){accounting.tables[1][2].chains["bw_mangle_POSTROUTING"].pop_back();driftOnPolicyWrite=false;}
  return result;
 }
};
static void resetIntegrated(){resetProjection();features=32767;}
static int accounting_regression_main(){unsigned startPoints=0,replacePoints=0;
 auto state=desired();auto other=desired(110001);auto invalid=accountingProgram;invalid.push_back("*filter");
 resetIntegrated();{AccountingCombined k;P p(k);C(p.startWithAccounting(invalid)==-EINVAL&&opens==0&&ioCount==0);C(p.startWithAccounting(accountingProgram)==0&&held&&opens==1);startPoints=ioCount;P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);ioCount=0;C(p.replace(state,0)==0&&!held&&opens==1&&files.size()==1);replacePoints=ioCount;checkState(p,10001,1);auto before=ioCount;C(p.startWithAccounting(accountingProgram)==-EALREADY&&ioCount==before&&!held);C(p.setDataSaver(false)==0&&!held);C(p.snapshot(&out,&g)==0&&g==2&&!out.policy.dataSaver());
  k.filter.tables[0].chains["bw_INPUT"].insert(k.filter.tables[0].chains["bw_INPUT"].begin(),"-A bw_INPUT -i wlan0 -j bw_costly_shared");auto quota=k.filter.tables[0].chains["bw_INPUT"];C(p.setDataSaver(true)==0&&k.filter.tables[0].chains["bw_INPUT"]==quota&&!held);
  k.accounting.tables[1][2].chains["bw_mangle_POSTROUTING"].pop_back();C(p.setDataSaver(false)==-EPROTO&&held&&files.empty());C(p.snapshot(&out,&g)==-EAGAIN);
 }
 for(unsigned bit=0;bit<15;++bit){resetIntegrated();features=32767^(1u<<bit);AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==-EOPNOTSUPP&&held&&files.empty()&&k.calls==0);}
 for(bool after:{false,true})for(unsigned point=1;point<=startPoints;++point){resetIntegrated();AccountingCombined k;P p(k);ioFault=point;ioAfter=after;C(p.startWithAccounting(accountingProgram)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 for(bool after:{false,true})for(unsigned point=1;point<=replacePoints;++point){resetIntegrated();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);ioCount=0;ioFault=point;ioAfter=after;C(p.replace(state,0)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.replace(other,0)==-ENOTCONN);}
 resetIntegrated();{AccountingCombined k;for(auto&f:k.hooks)for(auto&[n,r]:f){(void)n;r.clear();}P p(k);C(p.startWithAccounting(accountingProgram,P::HookMode::InstallMissing)==0&&held);C(p.replace(state,0)==0&&!held&&opens==1);}
 for(unsigned point:{startPoints/2,startPoints-2}){resetIntegrated();AccountingCombined k;P p(k);ioFault=point;ioAfter=true;C(p.startWithAccounting(accountingProgram)<0&&held&&files.empty());ioFault=0;C(p.startWithAccounting(accountingProgram)==0&&held);C(p.replace(state,0)==0&&!held);}
 resetIntegrated();{AccountingCombined k;k.accounting.tables[1][2].chains["bw_mangle_POSTROUTING"]={"-A bw_mangle_POSTROUTING -m bpf --object-pinned /old"};P p(k);C(p.startWithAccounting(accountingProgram)==-EPROTO&&k.filter.writes==0&&k.accounting.writes==0&&held&&files.empty());}
 resetIntegrated();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);k.driftOnPolicyWrite=true;C(p.replace(state,0)==-EPROTO&&held&&files.empty()&&lnaSets==0&&setCalls==0);P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==-EAGAIN);}
 resetIntegrated();{AccountingCombined k;k.denyControl=true;P p(k);auto root=state;assert(root.permissions.set(0,4)==0);C(p.startWithAccounting(accountingProgram)==0&&p.replace(root,0)==0&&!held);C(p.setDataSaver(false)<0&&held&&files.empty()&&kernelImage.front().uid==0&&kernelImage.front().permissions==4);}
 C(files.empty()&&held);printf("passed_cases=%u start_fault_points=%u replace_fault_points=%u\n",cases,startPoints,replacePoints);return 0;
}

#include <linux/netfilter/gta3xlwifi_packet_stats.h>
static unsigned largeStatsRows;static unsigned packetCalls,packetRetries,packetError;static int packetErrno;static bool packetBad,appRead;
extern "C" int underlyingIoctl(int fd,unsigned long cmd,...){
 va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);
 if(cmd!=GTA3XLWIFI_STATS_GET_STATE&&cmd!=GTA3XLWIFI_STATS_READ&&cmd!=GTA3XLWIFI_STATS_SWAP&&cmd!=GTA3XLWIFI_STATS_ACK&&cmd!=GTA3XLWIFI_STATS_EDIT)return ownerBaseIoctl(fd,cmd,arg);
 assert(files.count(fd)&&arg);++packetCalls;
 if(cmd==GTA3XLWIFI_STATS_GET_STATE){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_state*>(arg);gta3xlwifi_packet_stats_state zero{};assert(!memcmp(x,&zero,sizeof(zero)));x->version=1;x->active_epoch=1;x->bank_epoch[0]=1;x->total_stats_lost=UINT64_MAX;if(packetBad)x->version=2;}
 else if(cmd==GTA3XLWIFI_STATS_READ){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_transfer*>(arg);assert(x->version==1&&!x->reserved&&!x->lost_updates&&!x->sequence&&x->entries);
  if(appRead){assert(x->kind==2&&x->epoch==0&&x->count==10000);auto*rows=reinterpret_cast<gta3xlwifi_app_stats_entry*>(uintptr_t(x->entries));rows[0]={1,0,3,4,5,6};}
  else{assert(x->kind==1&&x->epoch==7&&x->count==5000);auto*rows=reinterpret_cast<gta3xlwifi_packet_stats_entry*>(uintptr_t(x->entries));rows[0]={{1,7,1,17},3,4,5,6};}
  if(largeStatsRows){for(unsigned i=0;i<largeStatsRows;++i){
 if(appRead){auto*r=reinterpret_cast<gta3xlwifi_app_stats_entry*>(uintptr_t(x->entries));r[i]={i+1,0,3,4,5,6};}
 else{auto*r=reinterpret_cast<gta3xlwifi_packet_stats_entry*>(uintptr_t(x->entries));r[i]={{i+1,7,1,17},3,4,5,6};}
 }}x->count=largeStatsRows?largeStatsRows:1;x->lost_updates=UINT64_MAX;x->sequence=UINT64_MAX;if(packetBad)x->version=2;
 }else if(cmd==GTA3XLWIFI_STATS_SWAP){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_swap*>(arg);assert(x->version==1&&x->active_bank==0&&x->active_epoch==1&&!x->inactive_bank&&!x->reserved&&!x->inactive_epoch);x->active_bank=1;x->active_epoch=2;x->inactive_bank=0;x->inactive_epoch=1;if(packetBad)x->version=2;}
 else if(cmd==GTA3XLWIFI_STATS_ACK){auto*x=reinterpret_cast<gta3xlwifi_packet_stats_ack*>(arg);assert(x->version==1&&x->bank==1&&x->epoch==7&&!x->reserved);}
 else{auto*x=reinterpret_cast<gta3xlwifi_packet_stats_edit*>(arg);assert(x->version==1&&x->uid==123&&!x->tag&&!x->reserved&&((x->operation==1&&x->counterset<=1)||(x->operation==2&&!x->counterset)));}
 if(packetRetries){--packetRetries;errno=EINTR;return -1;}if(packetError){errno=packetErrno;return packetError==2?1:-1;}return 0;
}
static void resetApi(){resetIntegrated();packetCalls=packetRetries=packetError=0;packetErrno=0;packetBad=appRead=false;}
struct Outputs{NetpolicyLease::PacketState state;NetpolicyLease::PacketSnapshot packet;NetpolicyLease::AppSnapshot app;NetpolicyLease::BankTransition transition;Outputs(){state.activeEpoch=99;packet.epoch=99;app.sequence=99;transition.activeEpoch=99;}bool unchanged()const{return state.activeEpoch==99&&packet.epoch==99&&app.sequence==99&&transition.activeEpoch==99;}};
static int operation(P&p,unsigned op,Outputs&o){appRead=op==2;switch(op){case 0:return p.readPacketState(&o.state);case 1:return p.readFrozenPacketStats(1,7,&o.packet);case 2:return p.readAppStats(&o.app);case 3:return p.swapPacketStats(0,1,&o.transition);case 4:return p.acknowledgePacketStats(1,7);case 5:return p.setPacketCounterset(123,1);case 6:return p.deleteUidPacketStats(123);default:assert(false);}}
static int baseline_runtime_regressions(){
 assert(accounting_regression_main()==0);unsigned before=cases;
 resetApi();{AccountingCombined k;P p(k);Outputs o;for(unsigned op=0;op<7;op++)C(operation(p,op,o)==-EAGAIN&&packetCalls==0&&o.unchanged());C(p.startWithAccounting(accountingProgram)==0);for(unsigned op=0;op<7;op++)C(operation(p,op,o)==-EAGAIN&&packetCalls==0&&o.unchanged()&&held);C(p.replace(desired(),0)==0&&!held&&opens==1);for(unsigned op=0;op<7;op++)C(operation(p,op,o)==0&&!held&&opens==1&&files.size()==1);C(o.state.activeEpoch==1&&o.state.totalStatsLost==UINT64_MAX);C(o.packet.entries.size()==1&&o.packet.epoch==7&&o.packet.entries[0].uid==1&&o.packet.entries[0].tag==7&&o.packet.entries[0].counterset==1&&o.packet.entries[0].ifindex==17&&o.packet.entries[0].txBytes==6&&o.packet.lostUpdates==UINT64_MAX);C(o.app.entries.size()==1&&o.app.entries[0].uid==1&&o.app.entries[0].txBytes==6&&o.app.sequence==UINT64_MAX);C(o.transition.activeBank==1&&o.transition.activeEpoch==2&&o.transition.inactiveEpoch==1);C(p.setPacketCounterset(123,0)==0);auto calls=packetCalls;C(p.readPacketState(nullptr)==-EINVAL);C(p.readFrozenPacketStats(2,7,&o.packet)==-EINVAL);C(p.readFrozenPacketStats(1,0,&o.packet)==-EINVAL);C(p.readAppStats(nullptr)==-EINVAL);C(p.swapPacketStats(0,UINT64_MAX,&o.transition)==-EINVAL);C(p.acknowledgePacketStats(2,7)==-EINVAL);C(p.setPacketCounterset(-1,1)==-EINVAL);C(p.setPacketCounterset(123,2)==-EINVAL);C(p.deleteUidPacketStats(-1)==-EINVAL&&packetCalls==calls&&!held);p.stop();for(unsigned op=0;op<7;op++)C(operation(p,op,o)==-EAGAIN&&packetCalls==calls&&held);}
 resetApi();{AccountingCombined k;P p(k);Outputs o;C(p.start()==0&&p.replace(desired(),0)==0&&!held);for(unsigned op=0;op<7;op++)C(operation(p,op,o)==-EOPNOTSUPP&&packetCalls==0&&o.unchanged()&&!held);P::State state;uint64_t g=0;C(p.snapshot(&state,&g)==0&&g==1);}
 for(unsigned op=0;op<7;op++)for(int error:{EIO,EFAULT,ENOMEM,ESTALE,ENOSPC,0}){resetApi();AccountingCombined k;P p(k);Outputs o;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);packetError=error?1:2;packetErrno=error;C(operation(p,op,o)==-(error?error:EPROTO)&&o.unchanged()&&files.empty()&&held&&packetCalls==1);P::State state;uint64_t g=77;C(p.snapshot(&state,&g)==-EAGAIN&&g==77);C(p.setDataSaver(false)==-EAGAIN);auto calls=packetCalls;C(operation(p,op,o)==-EAGAIN&&packetCalls==calls);}
 for(unsigned op=0;op<4;op++){resetApi();AccountingCombined k;P p(k);Outputs o;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);packetBad=true;C(operation(p,op,o)==-EPROTO&&o.unchanged()&&held&&files.empty());}
 for(unsigned op:{0u,1u,2u,4u}){resetApi();AccountingCombined k;P p(k);Outputs o;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);packetRetries=3;C(operation(p,op,o)==0&&!packetRetries&&packetCalls==4&&!held&&opens==1);}
 for(unsigned op:{3u,5u,6u}){resetApi();AccountingCombined k;P p(k);Outputs o;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);packetRetries=1;C(operation(p,op,o)==-EINTR&&o.unchanged()&&packetCalls==1&&files.empty()&&held);}
 C(files.empty()&&held);printf("owner_api_cases=%u total_cases=%u\n",cases-before,cases);return 0;
}

static int generic_runtime_regressions(){
 unsigned startPoints=0,replacePoints=0,committedPoints=0;auto a=desired(),b=desired(110001);
 resetProjection();{Combined k;P p(k);P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.replace(a,0)==-ENOTCONN&&ioCount==0);C(p.start()==0&&held&&opens==1);startPoints=ioCount;C(p.snapshot(&out,&g)==-EAGAIN);ioCount=0;C(p.replace(a,0)==0&&!held&&lnaSets==1&&setCalls==1&&opens==1);replacePoints=ioCount;checkState(p,10001,1);auto before=ioCount;C(p.replace(b,0)==-ESTALE&&ioCount==before);before=ioCount;C(p.replace(b,1)==0&&!held&&lnaRevision==2&&kernelRevision==2);committedPoints=ioCount-before;checkState(p,110001,2);C(p.removeUid(110001)==0&&!held);C(p.snapshot(&out,&g)==0&&g==3);uint32_t permissions=99;std::vector<int32_t> owners;std::vector<NetpolicyLease::LocalNetworkEntry> n,h;C(out.permissions.get(110001,&permissions)==0&&permissions==0&&out.ingress.ownerUids(&owners)==0&&owners.empty()&&out.local.snapshot(&n,&h)==0&&h.empty());}
 for(unsigned missing=0;missing<10;missing++){resetProjection();features=17407^(1u<<missing);Combined k;P p(k);C(p.start()==-EOPNOTSUPP&&held&&files.empty()&&k.calls==0);}
 for(bool after:{false,true})for(unsigned point=1;point<=startPoints;point++){resetProjection();Combined k;P p(k);ioFault=point;ioAfter=after;C(p.start()<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 for(bool after:{false,true})for(unsigned point=1;point<=replacePoints;point++){resetProjection();Combined k;P p(k);C(p.start()==0);ioCount=0;ioFault=point;ioAfter=after;C(p.replace(a,0)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.replace(b,0)==-ENOTCONN);}
 // The same quarantine guarantee holds AFTER a previous state was published.
 for(unsigned point:{1u,10u,committedPoints/2,committedPoints-2,committedPoints}){resetProjection();Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);ioCount=0;ioFault=point;ioAfter=true;C(p.replace(b,1)<0&&held&&files.empty());P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==-EAGAIN);}
 resetProjection();{Combined k;for(auto&f:k.hooks)for(auto&[n,r]:f)r.clear();P p(k);C(p.start(P::HookMode::InstallMissing)==0&&held);C(p.replace(a,0)==0&&!held);}
 // A shared-map overflow across otherwise valid independent components is pure
 // failure, not a partial policy change or a fabricated successful projection.
 resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);auto huge=a;for(int uid=10000;uid<30000;uid++)assert(huge.policy.setUidRule(11,uid,UidPolicy::Deny)==0);assert(huge.ingress.setIif(40000,0)==0);auto before=ioCount;C(p.replace(huge,1)==-E2BIG&&ioCount==before&&!held);checkState(p,10001,1);}
 resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);std::thread x([&]{assert(p.setIif(20001,18)==0);}),y([&]{assert(p.setUidPermission(20002,4)==0);}),z([&]{assert(p.setLockdown(20003,true)==0);});x.join();y.join();z.join();P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==0&&g==4&&!held&&opens==1);std::vector<int32_t> owners;C(out.ingress.ownerUids(&owners)==0&&owners==std::vector<int32_t>({10001,20001,20003}));uint32_t perm=0;C(out.permissions.get(20002,&perm)==0&&perm==4);}
 // Preserve the genuine NoInternet-root control corner; do not auto-clear it.
 resetProjection();{Combined k;k.denyControl=true;P p(k);auto root=a;assert(root.permissions.set(0,4)==0);C(p.start()==0&&p.replace(root,0)==0&&!held);C(p.setDataSaver(false)<0&&held&&files.empty()&&kernelImage.front().uid==0&&kernelImage.front().permissions==4);}
 resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);NetpolicyLease::LoopbackBatch batch;C(p.readLoopbackEvents(nullptr)==-EINVAL);C(p.readLoopbackEvents(&batch)==-ENOTTY&&held&&files.empty());P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==-EAGAIN);}
 resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(a,0)==0);NetpolicyLease::IfaceSnapshot counters;C(p.readIfaceStats(nullptr)==-EINVAL);C(p.readIfaceStats(&counters)==-EOPNOTSUPP&&held&&files.empty());P::State out;uint64_t g=0;C(p.snapshot(&out,&g)==-EAGAIN); }
 C(files.empty()&&held);printf("passed_cases=%u start_fault_points=%u replace_fault_points=%u\n",cases,startPoints,replacePoints);
return 0;}

#include <linux/netfilter/gta3xlwifi_runtime_policy.h>
using RI=NetpolicyLease::RuntimeImage;
static RI runtimeImage;static unsigned gets,sets,commits,metaRetries,dataRetries,setRetries,metaFault,dataFault;
static int runtimeGetError,runtimeSetError;static bool positiveGet,positiveSet,setAfterError;
extern "C" int __wrap_open(const char*p,int flags,...){int fd=underlyingOpen(p,flags);if(fd>=0&&std::string(p)=="/dev/gta3xlwifi_netpolicy")runtimeImage.confirmedForLease=false;return fd;}
extern "C" int __wrap_close(int fd){runtimeImage.confirmedForLease=false;return underlyingClose(fd);}
extern "C" int activeUnderlyingIoctl(int fd,unsigned long cmd,...){va_list ap;va_start(ap,cmd);unsigned long arg=va_arg(ap,unsigned long);va_end(ap);
 if(cmd==GTA3XLWIFI_NETPOLICY_RELEASE&&!runtimeImage.confirmedForLease){errno=EAGAIN;return -1;}
 if(cmd!=GTA3XLWIFI_RUNTIME_GET&&cmd!=GTA3XLWIFI_RUNTIME_SET)return underlyingIoctl(fd,cmd,arg);
 assert(files.count(fd)&&arg);bool bad=point();if(bad&&!ioAfter){errno=EIO;return -1;}auto*t=reinterpret_cast<gta3xlwifi_runtime_transfer*>(arg);assert(t->version==1&&!t->status);
 if(cmd==GTA3XLWIFI_RUNTIME_SET){firewallAllowed=false;++sets;assert(held&&(t->flags&~7)==0&&t->count<=1000&&bool(t->entries)==bool(t->count));std::vector<uint32_t> rows;
  if(t->count){auto*p=reinterpret_cast<const uint32_t*>(uintptr_t(t->entries));rows.assign(p,p+t->count);}
  if(runtimeSetError&&!setAfterError){errno=runtimeSetError;return positiveSet?1:-1;}
  if(t->revision==runtimeImage.revision&&t->flags==runtimeImage.flags&&rows==runtimeImage.legacyBlockedUids){}else{assert(t->revision==runtimeImage.revision+1);runtimeImage.revision=t->revision;runtimeImage.flags=t->flags;runtimeImage.legacyBlockedUids=rows;++commits;}
  runtimeImage.confirmedForLease=true;
  if(setRetries){--setRetries;errno=EINTR;return -1;}if(runtimeSetError){errno=runtimeSetError;return positiveSet?1:-1;}if(bad){errno=EIO;return -1;}return 0;
 }
 ++gets;assert(!t->flags);bool data=t->entries;uint64_t ptr=t->entries;
 if(data){assert(t->revision==runtimeImage.revision&&t->count==runtimeImage.legacyBlockedUids.size());auto*rows=reinterpret_cast<uint32_t*>(uintptr_t(ptr));std::copy(runtimeImage.legacyBlockedUids.begin(),runtimeImage.legacyBlockedUids.end(),rows);if(dataFault==7)rows[0]=UINT32_MAX;if(dataFault==8)rows[1]=rows[0];if(dataFault==9)std::swap(rows[0],rows[1]);}
 else assert(!t->revision&&!t->count);
 t->count=runtimeImage.legacyBlockedUids.size();t->revision=runtimeImage.revision;t->flags=runtimeImage.flags;t->status=runtimeImage.confirmedForLease?1:0;
 unsigned fault=data?dataFault:metaFault;switch(fault){case 0:break;case 1:t->version=2;break;case 2:++t->count;break;case 3:++t->revision;break;case 4:t->flags=8;break;case 5:t->status=2;break;case 6:t->entries=77;break;case 7:case 8:case 9:assert(data);break;case 10:t->revision=0;t->status=1;break;default:assert(false);}
 if(data&&dataRetries){--dataRetries;errno=EINTR;return -1;}if(!data&&metaRetries){--metaRetries;errno=EINTR;return -1;}if(runtimeGetError){errno=runtimeGetError;return positiveGet?1:-1;}if(bad){errno=EIO;return -1;}return 0;
}
static void resetRuntimeFixture(){runtimeImage={};gets=sets=commits=metaRetries=dataRetries=setRetries=metaFault=dataFault=0;runtimeGetError=runtimeSetError=0;positiveGet=positiveSet=setAfterError=false;}
static RI runtimeSentinel(){RI x;x.revision=99;x.flags=66;x.confirmedForLease=true;x.legacyBlockedUids={77};return x;}
static bool runtimeUnchanged(const RI&x){return x.revision==99&&x.flags==66&&x.confirmedForLease&&x.legacyBlockedUids==std::vector<uint32_t>{77};}

static int runtime_regressions(){
 C(generic_runtime_regressions()==0);C(baseline_runtime_regressions()==0);unsigned before=cases;
 resetApi();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);P::State unset;auto count=ioCount;C(p.replace(unset,0)==-EINVAL&&ioCount==count&&held);auto value=desired();value.runtime.flags=8;C(p.replace(value,0)==-EINVAL&&ioCount==count&&held);value=desired();value.runtime.legacyBlockedUids={2,1};C(p.replace(value,0)==-EINVAL&&ioCount==count&&held);value=desired();value.runtime.legacyBlockedUids={UINT32_MAX};C(p.replace(value,0)==-EINVAL&&ioCount==count&&held);C(p.replace(desired(),0)==0&&!held&&runtimeImage.confirmedForLease&&runtimeImage.flags==7);C(p.setRuntimePolicy(0,{10001,110001})==0&&!held&&runtimeImage.flags==0&&runtimeImage.legacyBlockedUids==std::vector<uint32_t>({10001,110001}));P::State out;uint64_t generation=0;C(!p.snapshot(&out,&generation)&&out.runtime.supplied&&out.runtime.flags==0&&out.runtime.legacyBlockedUids==runtimeImage.legacyBlockedUids);C(p.removeUid(10001)==0&&runtimeImage.legacyBlockedUids==std::vector<uint32_t>{110001});count=ioCount;C(p.setRuntimePolicy(8,{})==-EINVAL&&p.setRuntimePolicy(0,{2,1})==-EINVAL&&ioCount==count&&!held);}
 for(unsigned flags=0;flags<8;flags++){resetApi();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);auto s=desired();s.runtime={true,flags,{10001}};C(p.replace(s,0)==0&&!held&&runtimeImage.flags==flags&&runtimeImage.confirmedForLease);C(p.setDataSaver(false)==0&&runtimeImage.flags==flags&&!held);}
 for(unsigned fault:{1u,4u,5u,6u}){resetApi();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);metaFault=fault;C(p.setDataSaver(false)<0&&held&&files.empty()&&!runtimeImage.confirmedForLease);P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 resetApi();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);runtimeImage.flags=0;C(p.setDataSaver(false)==-EUCLEAN&&held&&files.empty());}
 resetApi();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);runtimeImage.confirmedForLease=false;C(p.setDataSaver(false)==-EUCLEAN&&held&&files.empty());}
 for(bool loop:{false,true}){resetApi();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);auto policy=desired();policy.permissions=android::net::gta3xlwifi::UidPermissionState{};android::net::gta3xlwifi::PermissionBootstrap::Snapshot f;f.users={0};f.knownUids={10001,10002};f.observed={{0,1023},{1000,1023},{10001,4}};f.loopbackPermissionEnabled=loop;C(p.publishInitialPermissions(policy,f)==0&&!held&&runtimeImage.confirmedForLease);P::State out;uint64_t g;uint32_t mask;C(!p.snapshot(&out,&g)&&!out.permissions.get(10002,&mask)&&mask==4&&out.runtime.flags==7);}
 C(files.empty()&&held);printf("runtime_owner_cases=%u total_cases=%u\n",cases-before,cases);return 0;
}

static int controller_regressions(){
 C(runtime_regressions()==0);const unsigned before=cases;unsigned preparePoints=0,finishPoints=0;
 resetApi();{AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==0&&held&&opens==1&&files.size()==1&&k.calls==0);preparePoints=ioCount;auto count=ioCount;C(p.prepareForControllerStartup()==-EALREADY&&p.start()==-EBUSY&&ioCount==count&&k.calls==0);P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.replace(desired(),0)==-ENOTCONN&&ioCount==count);auto invalid=accountingProgram;invalid[0]="*raw";C(p.startWithAccounting(invalid)==-EINVAL&&ioCount==count&&held&&opens==1);ioCount=0;C(p.startWithAccounting(accountingProgram)==0&&held&&opens==1);finishPoints=ioCount;C(p.replace(desired(),0)==0&&!held&&opens==1);C(p.prepareForControllerStartup()==-EALREADY);}
 for(unsigned bit=0;bit<15;++bit){resetApi();features=32767^(1u<<bit);AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==-EOPNOTSUPP&&held&&files.empty()&&k.calls==0);}
 for(bool after:{false,true})for(unsigned point=1;point<=preparePoints;++point){resetApi();AccountingCombined k;P p(k);ioFault=point;ioAfter=after;C(p.prepareForControllerStartup()<0&&held&&files.empty()&&k.calls==0);P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 for(bool after:{false,true})for(unsigned point=1;point<=finishPoints;++point){resetApi();AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==0);ioCount=0;ioFault=point;ioAfter=after;C(p.startWithAccounting(accountingProgram)<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 resetApi();{AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==0);held=false;auto count=k.calls;C(p.startWithAccounting(accountingProgram)==-EBUSY&&held&&files.empty()&&k.calls==count);}
 resetApi();{AccountingCombined k;P p(k);C(p.prepareForControllerStartup()==0);p.stop();C(held&&files.empty());C(p.prepareForControllerStartup()==0&&opens==1&&held);p.stop();C(held&&files.empty());}
 C(preparePoints>0&&finishPoints>60);printf("controller_owner_cases=%u prepare_fault_points=%u finish_fault_points=%u total_cases=%u\n",cases-before,preparePoints,finishPoints,cases);return 0;
}

static unsigned activeFault,activeRetries,activeCalls;static bool budgetFixture;
static std::vector<gta3xlwifi_packet_stats_entry> activeEntries;
extern "C" int statsBaseIoctl(int fd,unsigned long cmd,...){
 va_list args;va_start(args,cmd);unsigned long arg=va_arg(args,unsigned long);va_end(args);
 if(cmd==GTA3XLWIFI_STATS_GET_STATE&&budgetFixture){bool fail=point();if(fail&&!ioAfter){errno=EIO;return -1;}int result=activeUnderlyingIoctl(fd,cmd,arg);if(fail){errno=EIO;return -1;}return result;}
 if(cmd!=GTA3XLWIFI_STATS_READ||reinterpret_cast<gta3xlwifi_packet_stats_transfer*>(arg)->kind!=GTA3XLWIFI_STATS_ACTIVE)return activeUnderlyingIoctl(fd,cmd,arg);
 assert(files.count(fd)&&(!held||allowHeldActive)&&arg);++activeCalls;bool fail=point();if(fail&&!ioAfter){errno=EIO;return -1;}
 auto*t=reinterpret_cast<gta3xlwifi_packet_stats_transfer*>(arg);assert(t->version==1&&t->kind==3&&t->epoch==1&&t->count==5000&&t->entries&&!t->reserved&&!t->lost_updates&&!t->sequence);
 auto*rows=reinterpret_cast<gta3xlwifi_packet_stats_entry*>(uintptr_t(t->entries));std::copy(activeEntries.begin(),activeEntries.end(),rows);t->count=activeEntries.size();t->sequence=77;t->lost_updates=9;
 switch(activeFault){case 0:break;case 1:t->version=2;break;case 2:t->kind=1;break;case 3:++t->epoch;break;case 4:t->reserved=1;break;case 5:t->count=5001;break;case 6:++t->entries;break;case 7:rows[0].key.counterset=2;break;case 8:rows[1].key=rows[0].key;break;case 9:std::swap(rows[0],rows[2]);break;default:assert(false);}
 if(activeRetries){--activeRetries;errno=EINTR;return -1;}if(fail){errno=EIO;return -1;}return 0;
}
static void resetActive(){resetApi();budgetFixture=true;features=65535;activeFault=activeRetries=activeCalls=0;activeEntries={{{1,0,0,17},1,2,3,4},{{1,7,1,17},5,6,7,8},{{5,0,0,18},9,10,11,12}};}
static int active_regressions(){
 C(controller_regressions()==0);unsigned begin=cases,points=0;
 resetActive();{AccountingCombined k;P p(k);P::TaggingBudget out;out.totalEntries=99;C(p.readTaggingBudget(-1,&out)==-EINVAL&&p.readTaggingBudget(1,nullptr)==-EINVAL&&ioCount==0);C(p.readTaggingBudget(1,&out)==-EAGAIN&&out.totalEntries==99&&ioCount==0);C(p.startWithAccounting(accountingProgram)==0);C(p.readTaggingBudget(1,&out)==-EAGAIN&&held);C(p.replace(desired(),0)==0);ioCount=0;C(p.readTaggingBudget(1,&out)==0&&out.totalEntries==3&&out.uidEntries==2&&out.epoch==1&&out.sequence==77&&out.lostUpdates==9&&!held&&opens==1);points=ioCount;C(p.readTaggingBudget(5,&out)==0&&out.uidEntries==1&&out.totalEntries==3);C(p.readTaggingBudget(10001,&out)==0&&!out.uidEntries&&out.totalEntries==3);activeEntries.clear();C(p.readTaggingBudget(1,&out)==0&&!out.totalEntries&&!out.uidEntries&&out.lostUpdates==9);}
 for(unsigned f=1;f<=9;f++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);P::TaggingBudget out;out.totalEntries=99;activeFault=f;C(p.readTaggingBudget(1,&out)==-EPROTO&&out.totalEntries==99&&held&&files.empty());P::State state;uint64_t g=77;C(p.snapshot(&state,&g)==-EAGAIN&&g==77);}
 for(bool after:{false,true})for(unsigned i=1;i<=points;i++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);ioCount=0;ioFault=i;ioAfter=after;P::TaggingBudget out;out.totalEntries=99;C(p.readTaggingBudget(1,&out)<0&&out.totalEntries==99&&held&&files.empty());}
 resetActive();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);features=32767;P::TaggingBudget out;out.totalEntries=99;C(p.readTaggingBudget(1,&out)==-EOPNOTSUPP&&out.totalEntries==99&&held&&files.empty()&&!activeCalls);}
 resetActive();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);activeRetries=3;P::TaggingBudget out;C(p.readTaggingBudget(1,&out)==0&&activeCalls==4&&!activeRetries&&out.uidEntries==2&&!held);}
 resetProjection();{Combined k;P p(k);C(p.start()==0&&p.replace(desired(),0)==0);P::TaggingBudget out;auto count=ioCount;C(p.readTaggingBudget(1,&out)==-EOPNOTSUPP&&ioCount==count&&!held);}
 C(points>=5&&files.empty()&&held);printf("active_owner_cases=%u budget_fault_points=%u total_cases=%u\n",cases-begin,points,cases);return 0;
}

#include <atomic>
#include <thread>
#define PERMISSION_COUNT 7
#define UIDS_PER_INT64 (64 / PERMISSION_COUNT)
#define CHUNK_INT64_COUNT 128
#define CHUNK_UID_COUNT (CHUNK_INT64_COUNT * UIDS_PER_INT64)
#define PERMISSION_BIT_UPDATE_DEVICE_STATS (1 << 1)
#define AID_ROOT 0
#define AID_SYSTEM 1000
#define AID_DNS 1051
#define AID_CLAT 1029
#define AID_USER_OFFSET 100000

typedef struct {
    uint64_t block[CHUNK_INT64_COUNT];
} UidPermissionChunk;
namespace Oracle {
static uint32_t uid,mask;
constexpr uint32_t BPF_PERMISSION_UPDATE_DEVICE_STATS=8;
template<class T>struct Result{T data;bool ok()const{return true;}T value()const{return data;}};
struct Migration{Result<bool>readValue(uint32_t key){assert(key==0);return {true};}};
struct Chunk{Result<UidPermissionChunk>readValue(uint32_t key){assert(key==uid/CHUNK_UID_COUNT);UidPermissionChunk value{};value.block[uid/UIDS_PER_INT64%CHUNK_INT64_COUNT]=uint64_t(mask)<<((uid%UIDS_PER_INT64*PERMISSION_COUNT)&63);return {value};}};
struct Legacy{Result<uint32_t>readValue(uint32_t){assert(false);return {0};}};
struct Cookies{bool isValid(){return true;}};
struct BpfHandler{Migration mUidMigrationEnabledMap;Chunk mUidPermissionChunkMap;Legacy mUidPermissionMap;Cookies mCookieTagMap;bool hasUpdateDeviceStatsPermission(uid_t);int authorize(uint32_t chargeUid,uint32_t realUid);};
bool BpfHandler::hasUpdateDeviceStatsPermission(uid_t uid) {
    // This implementation is the same logic as method ActivityManager#checkComponentPermission.
    // It implies that real uid can never be same as AID_USER_OFFSET == PER_USER_RANGE == 100000
    uint32_t appId = uid % AID_USER_OFFSET;
    uint32_t mapKey = 0;
    auto isUidMigrationEnabled = mUidMigrationEnabledMap.readValue(mapKey);
    if (isUidMigrationEnabled.ok() && isUidMigrationEnabled.value()) {
        uint32_t chunkId = uid / CHUNK_UID_COUNT;
        uint32_t index = uid / UIDS_PER_INT64 % CHUNK_INT64_COUNT;
        int shift = (uid % UIDS_PER_INT64 * PERMISSION_COUNT) & 63;
        auto chunk = mUidPermissionChunkMap.readValue(chunkId);
        if (chunk.ok() && (chunk.value().block[index] >> shift) &
                              PERMISSION_BIT_UPDATE_DEVICE_STATS) {
            return true;
        }
    } else {
        auto permission = mUidPermissionMap.readValue(appId);
        if (permission.ok() &&
            (permission.value() & BPF_PERMISSION_UPDATE_DEVICE_STATS)) {
            return true;
        }
    }
    return ((appId == AID_ROOT) || (appId == AID_SYSTEM) || (appId == AID_DNS));
}
int BpfHandler::authorize(uint32_t chargeUid,uint32_t realUid){
    if (!mCookieTagMap.isValid()) return -EPERM;

    if (chargeUid != realUid && !hasUpdateDeviceStatsPermission(realUid)) return -EPERM;

    // Note that tagging the socket to AID_CLAT is only implemented in JNI ClatCoordinator.
    // The process is not allowed to tag socket to AID_CLAT via tagSocket() which would cause
    // process data usage accounting to be bypassed. Tagging AID_CLAT is used for avoiding counting
    // CLAT traffic data usage twice. See packages/modules/Connectivity/service/jni/
    // com_android_server_connectivity_ClatCoordinator.cpp
    if (chargeUid == AID_CLAT) return -EPERM;

return 0;}
}

struct Tagger:android::net::gta3xlwifi::SocketTagger{
 bool alive=true,drop=false;int result=0;unsigned tags=0,untags=0;uint32_t lastTag=0,lastUid=0;int lastFd=-1;std::function<void()> onTag;
 bool connected()const override{return alive;}
 int tagSocket(int fd,uint32_t tag,uid_t uid)override{assert(alive&&!held);++tags;lastTag=tag;lastUid=uid;lastFd=fd;if(onTag)onTag();if(drop)alive=false;return result;}
 int untagSocket(int fd)override{assert(alive&&!held);++untags;lastFd=fd;if(drop)alive=false;return result;}
};
static void budgetRows(unsigned total,unsigned perUid,uint32_t charge){activeEntries.clear();for(unsigned i=0;i<perUid;i++)activeEntries.push_back({{charge,i,0,17},0,0,0,0});for(unsigned i=perUid;i<total;i++)activeEntries.push_back({{uint32_t(charge+1),i,0,17},0,0,0,0});}
static int tagging_regressions(){
 C(active_regressions()==0);unsigned begin=cases,oracleCases=0;
 resetActive();{AccountingCombined k;P p(k);Tagger t;C(p.tagSocket(t,-1,0,1,1)==-EINVAL&&p.tagSocket(t,9,0,-1,1)==-EINVAL&&p.tagSocket(t,9,0,1,-1)==-EINVAL&&p.untagSocket(t,-1)==-EINVAL&&ioCount==0);C(p.tagSocket(t,9,0,1,1)==-EAGAIN&&p.untagSocket(t,9)==-EAGAIN&&!t.tags&&!t.untags);C(p.startWithAccounting(accountingProgram)==0&&p.tagSocket(t,9,0,1,1)==-EAGAIN);C(p.replace(desired(),0)==0);C(p.tagSocket(t,9,UINT32_MAX,1,1)==0&&t.lastTag==UINT32_MAX&&t.lastUid==1&&t.lastFd==9);C(p.untagSocket(t,9)==0&&t.untags==1);}
 for(int32_t real:{0,1000,1051,1029,10001,10002,100000,101000,101051,110001,201051,INT32_MAX}){
  resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);
  for(unsigned mask=0;mask<128;mask++){
   C(p.setUidPermission(real,mask)==0);Oracle::uid=real;Oracle::mask=mask;Oracle::BpfHandler oracle;
   for(int32_t charge:{real,10001,10002,1029,110001}){auto before=t.tags;auto points=ioCount;int expected=oracle.authorize(charge,real);int result=p.tagSocket(t,9,7,charge,real);C(result==expected&&!held&&opens==1);C(t.tags==before+(expected==0));if(expected)C(ioCount==points);++oracleCases;}
  }
 }
 for(auto pair:{std::pair<unsigned,unsigned>{0,0},{500,500},{501,501},{4500,500},{4501,500},{4500,501},{5000,1}}){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);budgetRows(pair.first,pair.second,10001);auto before=t.tags;int expected=pair.first>4500||pair.second>500?-EMFILE:0;C(p.tagSocket(t,9,7,10001,10001)==expected&&!held);C(t.tags==before+(expected==0));}
 for(int error:{-EBADF,-ENOTSOCK,-EAFNOSUPPORT,-EPROTONOSUPPORT,-EMFILE,-EINVAL,-EPERM,-EIO}){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);t.result=error;C(p.tagSocket(t,9,7,1,1)==error&&!held&&opens==1);C(p.untagSocket(t,9)==error&&!held);t.result=0;C(p.tagSocket(t,9,7,1,1)==0&&!held);}
 for(bool untag:{false,true})for(int error:{0,-EIO,1}){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);t.result=error;t.drop=true;int result=untag?p.untagSocket(t,9):p.tagSocket(t,9,7,1,1);C(result==(error<0?error:-EPROTO)&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 for(bool untag:{false,true}){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);t.alive=false;C((untag?p.untagSocket(t,9):p.tagSocket(t,9,7,1,1))==-ENOTCONN&&held&&files.empty()&&!t.tags&&!t.untags);}
 for(bool after:{false,true})for(unsigned i=1;i<=5;i++){resetActive();AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);ioCount=0;ioFault=i;ioAfter=after;C(p.tagSocket(t,9,7,1,1)<0&&held&&files.empty()&&!t.tags);}
 resetActive();{AccountingCombined k;P p(k);Tagger t;C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0&&p.setUidPermission(10001,2)==0);std::atomic<bool> attempted=false,done=false;std::thread writer;t.onTag=[&]{writer=std::thread([&]{attempted=true;assert(!p.setUidPermission(10001,0));done=true;});while(!attempted.load())std::this_thread::yield();assert(!done.load());};C(p.tagSocket(t,9,7,10002,10001)==0);writer.join();C(done.load());t.onTag={};auto before=t.tags;C(p.tagSocket(t,9,7,10002,10001)==-EPERM&&t.tags==before&&!held);}
 C(files.empty()&&held&&oracleCases==7680);printf("tagging_owner_cases=%u oracle_comparisons=%u total_cases=%u\n",cases-begin,oracleCases,cases);return 0;
}

static int provider_regressions(){
 C(tagging_regressions()==0);unsigned begin=cases,verifyPoints=0;allowHeldActive=true;
 resetActive();{AccountingCombined k;P p(k);C(p.verifyHeldProviderStartup()==-ENOTCONN&&ioCount==0);C(p.prepareForControllerStartup()==0);auto before=ioCount;C(p.verifyHeldProviderStartup()==-ENOTCONN&&ioCount==before&&held);C(p.startWithAccounting(accountingProgram)==0);ioCount=0;C(p.verifyHeldProviderStartup()==0&&held&&opens==1);verifyPoints=ioCount;P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);C(p.verifyHeldProviderStartup()==0&&held&&opens==1);C(p.replace(desired(),0)==0);before=ioCount;C(p.verifyHeldProviderStartup()==-EALREADY&&ioCount==before&&!held);}
 for(bool after:{false,true})for(unsigned point=1;point<=verifyPoints;point++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);ioCount=0;ioFault=point;ioAfter=after;C(p.verifyHeldProviderStartup()<0&&held&&files.empty());P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);auto count=ioCount;C(p.verifyHeldProviderStartup()==-ENOTCONN&&ioCount==count);}
 for(unsigned bit=0;bit<16;bit++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);features=65535^(1u<<bit);C(p.verifyHeldProviderStartup()==-EOPNOTSUPP&&held&&files.empty());}
 for(unsigned fault=1;fault<=9;fault++){resetActive();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);activeFault=fault;C(p.verifyHeldProviderStartup()==-EPROTO&&held&&files.empty());}
 resetActive();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);held=false;auto before=k.calls;C(p.verifyHeldProviderStartup()==-EBUSY&&held&&files.empty()&&k.calls==before);}
 resetProjection();{Combined k;P p(k);C(p.start()==0);auto before=ioCount;C(p.verifyHeldProviderStartup()==-EOPNOTSUPP&&ioCount==before&&held);}
 C(files.empty()&&held&&verifyPoints>30);printf("held_provider_owner_cases=%u verification_fault_points=%u total_cases=%u\n",cases-begin,verifyPoints,cases);return 0;
}

#include "Gta3xlwifiPolicyFrame.h"
#include "Gta3xlwifiNetpolicyService.h"
#include <binder/IPCThreadState.h>
#include <random>
using Frame=android::net::gta3xlwifi::PolicyFrame;
using Service=android::net::gta3xlwifi::NetpolicyService;
using android::IBinder;using android::sp;
using Sections=std::array<std::vector<int32_t>,Frame::SectionCount>;
static Sections image(){Sections v;v[Frame::Users]={0};v[Frame::KnownUids]={10001,10002};v[Frame::RawPermissions]={0,1023,1000,1023,10001,4};for(const auto&c:android::net::gta3xlwifi::UidPolicy::chains()){v[Frame::ChainConfiguration].push_back(c.id);v[Frame::ChainConfiguration].push_back(0);}return v;}
static std::vector<int32_t>counts(const Sections&v){std::vector<int32_t>r;for(auto&s:v)r.push_back(s.size());return r;}
static void fill(Frame&f,const Sections&v,unsigned chunk=4096){for(unsigned i=0;i<v.size();++i)for(unsigned offset=0;offset<v[i].size();offset+=chunk){auto end=std::min(offset+chunk,(unsigned)v[i].size());C(f.append(i,offset,{v[i].begin()+offset,v[i].begin()+end})==0);}}
static int compile(const Sections&v,P::State*out){Frame f;int e=f.begin(counts(v),7,true,true,true);if(e)return e;fill(f,v);return f.compile(out);}
static void reject(const Sections&v,int e){P::State out;out.policy.setDataSaver(true);C(compile(v,&out)==e&&out.policy.dataSaver());}
static void send(Service&s,int64_t session,int64_t generation,const Sections&v,unsigned chunk=4096){C(s.beginFrame(session,generation,counts(v),7,true,true,true).isOk());for(unsigned i=0;i<v.size();++i)for(unsigned off=0;off<v[i].size();off+=chunk){auto end=std::min(off+chunk,(unsigned)v[i].size());C(s.appendFrame(session,i,off,{v[i].begin()+off,v[i].begin()+end}).isOk());}}
static int previous_owner_regressions(){
 C(provider_regressions()==0);allowHeldActive=true;unsigned begin=cases;
 Frame frame;P::State output;C(frame.compile(&output)==-ENOTCONN);C(frame.append(0,0,{0})==-ENOTCONN);C(frame.begin(counts(image()),7,true,false,false)==-EOPNOTSUPP);C(frame.begin(counts(image()),8,true,true,false)==-EINVAL);
 C(frame.begin(counts(image()),7,true,true,false)==0);C(frame.begin(counts(image()),7,true,true,false)==-EBUSY);C(frame.compile(&output)==-EAGAIN);C(frame.append(100,0,{1})==-EINVAL);C(frame.append(0,1,{0})==-ESTALE);C(frame.append(0,0,{})==-EINVAL);C(frame.append(0,0,{0,1})==-E2BIG);C(frame.append(0,0,std::vector<int32_t>(4097))==-EINVAL);fill(frame,image(),1);C(frame.compile(&output)==0);uint32_t mask=99;C(!output.permissions.get(10001,&mask)&&mask==0);C(!output.permissions.get(10002,&mask)&&mask==4);C(!output.permissions.get(0,&mask)&&mask==123);C(output.runtime.supplied&&output.runtime.flags==7);C(frame.append(0,0,{0})==-ESTALE);frame.clear();C(frame.compile(&output)==-ENOTCONN);
 for(unsigned i=0;i<10;++i){auto n=counts(image());n[i]=-1;Frame f;C(f.begin(n,7,false,true,false)==-EINVAL);n[i]=INT32_MAX;C(f.begin(n,7,false,true,false)==-EINVAL);}
 {auto v=image();v[Frame::Users]={0,0};reject(v,-EINVAL);v=image();v[Frame::Users]={1};reject(v,-EPROTO);v=image();v[Frame::RawPermissions][1]=1022;reject(v,-EPROTO);v=image();v[Frame::RawPermissions][5]=1024;reject(v,-EINVAL);v=image();v[Frame::RawPermissions].insert(v[Frame::RawPermissions].end(),{10001,4});reject(v,-EINVAL);}
 {auto v=image();v[Frame::ChainConfiguration][2]=1;reject(v,-EINVAL);v=image();v[Frame::ChainConfiguration][1]=2;reject(v,-EINVAL);v=image();v[Frame::ChainMembership]={42,10001};reject(v,-EINVAL);v[Frame::ChainMembership]={1,-1};reject(v,-EINVAL);v[Frame::ChainMembership]={1,10001,1,10001};reject(v,-EINVAL);}
 {auto v=image();v[Frame::IngressOwners]={10001,0,1,0};reject(v,-EINVAL);v[Frame::IngressOwners]={10001,2,0,0};reject(v,-EINVAL);v[Frame::IngressOwners]={10001,1,-1,0};reject(v,-EINVAL);v[Frame::IngressOwners]={10001,1,0,0,10001,0,0,1};reject(v,-EINVAL);v[Frame::IngressOwners]={10001,1,0,1};C(!compile(v,&output));}
 {auto v=image();v[Frame::DiscardAddresses]={0,0,0,0,0,0};reject(v,-EINVAL);v[Frame::DiscardAddresses]={0,0,0,1,0,1,0,0,0,1,0,1};reject(v,-EINVAL);v[Frame::DiscardAddresses]={0,0,0,1,0,-1};reject(v,-EINVAL);v[Frame::DiscardAddresses]={0,0,0,1,0,1};C(!compile(v,&output));}
 for(auto section:{Frame::LocalNetworks,Frame::LocalHosts}){auto v=image();v[section]={193,0,0,0,0,0,0,0};reject(v,-EINVAL);v[section]={0,0,0,0,0,0,0,2};reject(v,-EINVAL);v[section]={0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,1};reject(v,-EEXIST);v[section]={192,0x01020304,0,0,0,0,0,0};C(!compile(v,&output));std::vector<android::net::gta3xlwifi::LocalNetworkState::Entry>network,host;C(!output.local.snapshot(&network,&host));const auto&e=section==Frame::LocalNetworks?network[0]:host[0];C(e.key[0]==1&&e.key[1]==2&&e.key[2]==3&&e.key[3]==4&&!e.allowed);}
 {auto v=image();v[Frame::LegacyBlockedUids]={10002,10001};reject(v,-EINVAL);v[Frame::LegacyBlockedUids]={10001,10001};reject(v,-EINVAL);v[Frame::LegacyBlockedUids]={-1};reject(v,-EINVAL);v[Frame::LegacyBlockedUids]={10001,10002};C(!compile(v,&output)&&output.runtime.legacyBlockedUids.size()==2);}
 // Full 65,536 known-UID boundary, observed INTERNET-only entries and zero-raw missing entries.
 {auto v=image();v[Frame::KnownUids]={0,1000};for(int i=10000;i<75534;++i)v[Frame::KnownUids].push_back(i);C(!compile(v,&output));C(!output.permissions.get(75533,&mask)&&mask==4);v[Frame::KnownUids].push_back(75536);reject(v,-EINVAL);}
 // Random chunk partitions must yield the same real state for all 128 canonical permissions.
 for(unsigned seed=1;seed<=128;++seed){auto v=image();v[Frame::RawPermissions][5]=(seed*7)&1023;Frame f;C(!f.begin(counts(v),seed&7,true,true,seed&1));fill(f,v,1+seed%17);C(!f.compile(&output));uint32_t canonical;C(!android::net::gta3xlwifi::PermissionBootstrap::convert((seed*7)&1023,true,&canonical));C(!output.permissions.get(10001,&mask)&&mask==canonical);}
 resetActive();{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=77,generation=77;
 for(uint32_t uid:{0u,1001u,1051u,1073u,10000u,101000u,UINT32_MAX}){android::IPCThreadState::uid=uid;C(service->openSession(client,1,&session).exception==-1&&session==77);C(service->beginFrame(1,0,counts(image()),7,true,true,true).exception==-1);C(service->appendFrame(1,0,0,{0}).exception==-1);C(service->commitFrame(1,&generation).exception==-1&&generation==77);C(service->abandonFrame(1).exception==-1);}
 android::IPCThreadState::uid=1000;C(service->openSession({},1,&session).code==EINVAL);C(service->openSession(client,2,&session).code==EINVAL);client->linkError=-1;C(service->openSession(client,1,&session).code==EPIPE);client->linkError=0;C(service->openSession(client,1,&session).isOk()&&session>0);int64_t again=0;C(service->openSession(client,1,&again).isOk()&&again==session);C(service->openSession(sp<IBinder>::make(),1,&again).code==EBUSY);C(service->commitFrame(session+1,&generation).code==ESTALE);C(service->commitFrame(session,&generation).code==ENOTCONN);C(service->beginFrame(session,1,counts(image()),7,true,true,true).code==ESTALE);C(service->beginFrame(session,-1,counts(image()),7,true,true,true).code==EINVAL);
 send(*service,session,0,image(),1);C(service->appendFrame(session,-1,0,{0}).code==EINVAL);C(service->appendFrame(session,0,-1,{0}).code==EINVAL);C(service->appendFrame(session,0,0,{0}).code==ESTALE);C(service->commitFrame(session,&generation).isOk()&&generation==1&&!held);C(!owner.snapshot(&output,(uint64_t*)&again));C(!output.permissions.get(10002,&mask)&&mask==4);
 C(service->beginFrame(session,0,counts(image()),7,true,true,true).code==ESTALE);send(*service,session,generation,image());C(service->abandonFrame(session).isOk()&&!held);C(service->commitFrame(session,&again).code==ENOTCONN);
 // Death while a frame is staged holds traffic and removes publication. A stale death from
 // that old binder must not revoke the new session, even after its next successful commit.
 send(*service,session,generation,image());auto oldDeaths=client->deaths;client->kill();C(held);uint64_t outGeneration=99;C(owner.snapshot(&output,&outGeneration)==-EAGAIN&&outGeneration==99);C(service->commitFrame(session,&again).code==ESTALE);
 auto nextClient=sp<IBinder>::make();int64_t nextSession=0;C(service->openSession(nextClient,1,&nextSession).isOk()&&nextSession>session);send(*service,nextSession,0,image());C(service->commitFrame(nextSession,&generation).isOk()&&generation==2&&!held);for(auto&d:oldDeaths)d->binderDied({});C(!held);C(service->abandonFrame(nextSession).isOk());
 // Repeated permission revocation/grant images advance exactly one generation each.
 for(int i=0;i<40;++i){auto v=image();v[Frame::RawPermissions][5]=i%2?4:0;send(*service,nextSession,generation,v,3);C(service->commitFrame(nextSession,&generation).isOk()&&generation==3+i);uint64_t g;C(!owner.snapshot(&output,&g)&&g==(uint64_t)generation);C(!output.permissions.get(10001,&mask)&&mask==(i%2?0u:4u));}
 nextClient->kill();C(held);C(owner.snapshot(&output,&outGeneration)==-EAGAIN);
 }
 // Every HOLD failure before/after actual fixture effect closes/holds the lease.
 for(bool after:{false,true})for(unsigned point=1;point<=2;++point){resetActive();AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));uint64_t g=0;C(!owner.replaceWithGeneration(desired(),0,&g)&&g==1);ioCount=0;ioFault=point;ioAfter=after;C(owner.suspendFrameworkClient()<0&&held&&files.empty());C(owner.snapshot(&output,&g)==-EAGAIN);}

 resetActive();{AccountingCombined kernel;P owner(kernel);uint64_t rawGeneration=777;C(owner.frameworkGeneration(&rawGeneration)==-ENOTCONN&&rawGeneration==777);C(owner.frameworkGeneration(nullptr)==-EINVAL);C(!owner.startWithAccounting(accountingProgram));C(!owner.frameworkGeneration(&rawGeneration)&&rawGeneration==0);auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=0,generation=777;C(service->openSession(client,1,&session).isOk());
 for(uint32_t uid:{0u,1001u,1051u,1073u,10000u,101000u,UINT32_MAX}){android::IPCThreadState::uid=uid;C(service->readGeneration(session,&generation).exception==-1&&generation==777);C(service->closeSession(client).exception==-1);}
 android::IPCThreadState::uid=1000;C(service->readGeneration(session+1,&generation).code==ESTALE&&generation==777);C(service->readGeneration(session,&generation).isOk()&&generation==0);C(service->closeSession(sp<IBinder>::make()).code==ESTALE);C(service->closeSession({}).code==ESTALE);
 // Simultaneous begins and repeated same-offset chunks are serialized without duplication.
 android::binder::Status first,second;
 std::thread a([&]{first=service->beginFrame(session,0,counts(image()),7,true,true,true);});std::thread b([&]{second=service->beginFrame(session,0,counts(image()),7,true,true,true);});a.join();b.join();C((first.isOk()&&second.code==EBUSY)||(second.isOk()&&first.code==EBUSY));
 std::thread c([&]{first=service->appendFrame(session,0,0,{0});});std::thread d([&]{second=service->appendFrame(session,0,0,{0});});c.join();d.join();C((first.isOk()&&second.code==ESTALE)||(second.isOk()&&first.code==ESTALE));C(service->abandonFrame(session).isOk());
 send(*service,session,0,image());C(service->commitFrame(session,&generation).isOk()&&generation==1&&!held);C(service->readGeneration(session,&generation).isOk()&&generation==1);auto oldDeaths=client->deaths;C(service->closeSession(client).isOk()&&held&&client->deaths.empty());C(service->readGeneration(session,&generation).code==ESTALE);C(service->closeSession(client).code==ESTALE);
 auto next=sp<IBinder>::make();int64_t nextSession=0;C(service->openSession(next,1,&nextSession).isOk()&&nextSession>session);C(service->readGeneration(nextSession,&generation).isOk()&&generation==0);send(*service,nextSession,0,image());C(service->commitFrame(nextSession,&generation).isOk()&&generation==2&&!held);for(auto&death:oldDeaths)death->binderDied({});C(!held);C(service->closeSession(client).code==ESTALE&&!held);C(service->closeSession(next).isOk()&&held);
 }
 // Commit vs death has two valid orderings, both finish held/unpublished.
 for(unsigned attempt=0;attempt<10;++attempt){resetActive();AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=0,generation=0;C(service->openSession(client,1,&session).isOk());send(*service,session,0,image());android::binder::Status result;std::thread a([&]{result=service->commitFrame(session,&generation);});std::thread b([&]{client->kill();});a.join();b.join();C(result.isOk()||result.code==ESTALE);C(held);uint64_t gen=777;C(owner.snapshot(&output,&gen)==-EAGAIN&&gen==777);}
 C(files.empty()&&held);printf("policy_frame_service_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}

#include "LegacyDnsPolicy.h"
#include <atomic>
#include <memory>
static bool dnsLegacy=true,dnsMetered=false,dnsEnforce=false;static int dnsExperiment=1,stockInitCalls=0,stockReads=0;
namespace android::base{
static bool GetBoolProperty(const char*,bool){return dnsLegacy;}
class Error{int mCode;public:explicit Error(int code):mCode(code){}int code()const{return mCode;}template<class T>Error&operator<<(const T&){return *this;}};
template<class T>class Result{bool mOk=true;T mValue{};Error mError{0};public:Result(T value):mValue(value){}Result(const Error&e):mOk(false),mError(e){}bool ok()const{return mOk;}const Error&error()const{return mError;}T value()const{return mValue;}};
template<>class Result<void>{bool mOk=true;Error mError{0};public:Result()=default;Result(const Error&e):mOk(false),mError(e){}bool ok()const{return mOk;}const Error&error()const{return mError;}};
}
namespace android::net{
static LegacyDnsPolicy sLegacyDnsPolicy;
class DnsHelperFixture{public:base::Result<void>init(){
if (base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
    if (!sLegacyDnsPolicy.registered()) return base::Error(ENOTCONN) << "No held owner callback";
    return {};  // Verified held transport only. Query remains EAGAIN until commit.
  }
++stockInitCalls;return {};}
base::Result<bool>isUidNetworkingBlocked(uid_t uid,bool metered){
if (base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
    const int decision = sLegacyDnsPolicy.evaluate(uid, metered);
    if (decision < 0) return base::Error(-decision) << "Private policy unavailable";
    return decision == 1;
  }
++stockReads;return false;}};
}
static android::net::DnsHelperFixture sDnsBpfHelper;
int ADnsHelper_init() {
  auto result = sDnsBpfHelper.init();
  if (!result.ok()) return -result.error().code();

  return 0;
}
int ADnsHelper_isUidNetworkingBlocked(uid_t uid, bool metered) {
  auto result = sDnsBpfHelper.isUidNetworkingBlocked(uid, metered);
  if (!result.ok()) return -result.error().code();

  // bool -> int conversion.
  return result.value();
}
extern "C" int ADnsHelper_setLegacyCallbackV2(int (*callback)(uid_t, bool)) {
  if (!android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) return -EOPNOTSUPP;
  return android::net::sLegacyDnsPolicy.setCallback(callback);
}
extern "C" int resolv_set_gta3xlwifi_policy(int (*callback)(uid_t, bool)) {
    return ADnsHelper_setLegacyCallbackV2(callback);
}
namespace DnsAdapter{P* owner=nullptr;
int blocked(uid_t uid, bool metered) {
    if (uid > INT_MAX) return -EINVAL;
    return owner ? owner->isNetworkingBlocked(uid, metered) : -ENOTCONN;
}
}
namespace ProxyFixture{
static bool isAtLeastT(){return true;}
static bool resolv_is_enforceDnsUid_enabled_network(unsigned){return dnsEnforce;}
static bool resolv_is_metered_network(unsigned){return dnsMetered;}
struct Experiments{static Experiments*getInstance(){static Experiments e;return &e;}int getFlag(const char*,int){return dnsExperiment;}};
bool isUidNetworkingBlocked(uid_t uid, unsigned netId) {
    static const bool hasBPF = isAtLeastT();  // Related BPF maps were only mainlined from T.
    const bool privateBackend = android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false);
    if (!privateBackend && !hasBPF) return false;

    // The enforceDnsUid is an OEM feature that sets DNS packet with AID_DNS instead of the
    // application's UID. Its DNS packets are not subject to certain network restriction features.
    if (resolv_is_enforceDnsUid_enabled_network(netId)) return false;

    // Feature flag that can disable the feature.
    if (!Experiments::getInstance()->getFlag("fail_fast_on_uid_network_blocking", 1)) return false;

    const int decision = ADnsHelper_isUidNetworkingBlocked(uid, resolv_is_metered_network(netId));
    // Preserve upstream OEM/experiment fast-fail controls above. On the private
    // path missing/unpublished/failed policy is never converted into allow.
    return privateBackend ? decision != 0 : decision == 1;
}
}
static int malformed(uid_t uid,bool){return uid==0?2:uid==1?INT_MIN:-4096;}
static int alternate(uid_t,bool){return 0;}
static void resetDns(){std::destroy_at(&android::net::sLegacyDnsPolicy);std::construct_at(&android::net::sLegacyDnsPolicy);dnsLegacy=true;dnsMetered=false;dnsEnforce=false;dnsExperiment=1;stockInitCalls=stockReads=0;}
static int previous_stats_regressions(){C(previous_owner_regressions()==0);allowHeldActive=true;unsigned begin=cases;
 // The preflight and daemon use distinct owners but the SAME retained rule
 // images/kernel state. No fixture reset between the two lifetimes.
 resetActive();{AccountingCombined kernel;
  {P preflight(kernel);C(!preflight.startWithAccounting(accountingProgram));C(!preflight.verifyHeldProviderStartup());C(held);preflight.stop();C(held&&files.empty());}
  {P daemon(kernel);C(!daemon.startWithAccounting(accountingProgram));C(!daemon.verifyHeldProviderStartup());C(held);C(!daemon.replace(desired(),0));C(!held);daemon.stop();C(held&&files.empty());}
 }

 resetActive();resetDns();{AccountingCombined kernel;P owner(kernel);DnsAdapter::owner=&owner;C(owner.isNetworkingBlocked(10001,false)==-EAGAIN);C(owner.isNetworkingBlocked(-1,false)==-EINVAL);C(!owner.startWithAccounting(accountingProgram));C(!owner.verifyHeldProviderStartup());C(ADnsHelper_init()==-ENOTCONN&&stockInitCalls==0);C(resolv_set_gta3xlwifi_policy(nullptr)==-EINVAL);C(resolv_set_gta3xlwifi_policy(DnsAdapter::blocked)==0);C(resolv_set_gta3xlwifi_policy(DnsAdapter::blocked)==0);C(resolv_set_gta3xlwifi_policy(alternate)==-EALREADY);C(ADnsHelper_init()==0&&held&&stockInitCalls==0);C(ADnsHelper_isUidNetworkingBlocked(10001,false)==-EAGAIN);C(ProxyFixture::isUidNetworkingBlocked(10001,1));C(ADnsHelper_isUidNetworkingBlocked(UINT_MAX,false)==-EINVAL);C(ProxyFixture::isUidNetworkingBlocked(UINT_MAX,1));C(!owner.replace(desired(),0));
 for(bool metered:{false,true})for(int uid:{0,1000,10001,10002,1010001,INT_MAX}){P::State state;uint64_t generation;C(!owner.snapshot(&state,&generation));int expected=state.policy.isNetworkingBlocked(uid,metered);C(ADnsHelper_isUidNetworkingBlocked(uid,metered)==expected);dnsMetered=metered;C(ProxyFixture::isUidNetworkingBlocked(uid,1)==(expected==1));}
 for(unsigned n=0;n<20;++n){C(!owner.setDataSaver(n%2));for(bool metered:{false,true}){P::State state;uint64_t g;C(!owner.snapshot(&state,&g));C(ADnsHelper_isUidNetworkingBlocked(10002,metered)==state.policy.isNetworkingBlocked(10002,metered));}}
 std::atomic<unsigned>reads{0},bad{0};std::thread reader([&]{for(unsigned n=0;n<200;n++){int r=ADnsHelper_isUidNetworkingBlocked(10001,true);if(r!=0&&r!=1)++bad;++reads;}});for(unsigned n=0;n<10;n++)C(!owner.setDataSaver(n%2));reader.join();C(reads==200&&bad==0);
 C(!owner.suspendFrameworkClient()&&held);C(ADnsHelper_isUidNetworkingBlocked(0,false)==-EAGAIN);C(ProxyFixture::isUidNetworkingBlocked(10001,1));dnsExperiment=0;C(!ProxyFixture::isUidNetworkingBlocked(10001,1)&&held);dnsExperiment=1;dnsEnforce=true;C(!ProxyFixture::isUidNetworkingBlocked(10001,1)&&held);dnsEnforce=false;C(stockReads==0&&stockInitCalls==0);C(!owner.replace(desired(),0));ioCount=0;ioFault=1;ioAfter=false;C(owner.setDataSaver(true)<0&&held&&files.empty());C(ADnsHelper_isUidNetworkingBlocked(10001,false)==-EAGAIN&&ProxyFixture::isUidNetworkingBlocked(10001,1));DnsAdapter::owner=nullptr;C(ADnsHelper_isUidNetworkingBlocked(10001,false)==-ENOTCONN);}
 resetDns();C(resolv_set_gta3xlwifi_policy(malformed)==0);for(uid_t uid:{0u,1u,2u}){C(ADnsHelper_isUidNetworkingBlocked(uid,false)==-EPROTO);C(ProxyFixture::isUidNetworkingBlocked(uid,1));}dnsLegacy=false;C(resolv_set_gta3xlwifi_policy(alternate)==-EOPNOTSUPP);C(ADnsHelper_init()==0&&stockInitCalls==1);C(!ProxyFixture::isUidNetworkingBlocked(10001,1)&&stockReads==1);C(files.empty()&&held);
 printf("dns_owner_cases=%u prior_plus_new_cases=%u concurrent_reads=%u\n",cases-begin,cases,200u);return 0;
}

#include <linux/netfilter/gta3xlwifi_iface_stats.h>
extern "C" int __wrap_ioctl(int fd,unsigned long command,...){va_list v;va_start(v,command);unsigned long arg=va_arg(v,unsigned long);va_end(v);
 if(command!=GTA3XLWIFI_IFACE_STATS_GET)return statsBaseIoctl(fd,command,arg);
 assert(files.count(fd)&&arg);auto*x=reinterpret_cast<gta3xlwifi_iface_stats_transfer*>(arg);
 assert(x->version==1&&x->count==1000&&x->entries&&!x->lost_updates&&!x->update_sequence);
 auto*rows=reinterpret_cast<gta3xlwifi_iface_stats_entry*>(uintptr_t(x->entries));rows[0]={17,0,UINT64_MAX,1,2,3};x->count=1;x->lost_updates=UINT64_MAX;x->update_sequence=UINT64_MAX;return 0;
}
int main(){C(!previous_stats_regressions());unsigned begin=cases;
 resetActive();{AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=0,g=0;android::IPCThreadState::uid=1000;C(service->openSession(client,1,&session).isOk());std::vector<int64_t>out{777};
 for(uint32_t uid:{0u,1001u,1051u,1073u,10000u,101000u,UINT32_MAX}){android::IPCThreadState::uid=uid;auto n=ioCount;C(service->readStats(session,0,0,0,&out).exception==-1);C(service->swapStats(session,0,1,&out).exception==-1);C(service->acknowledgeStats(session,1,7).exception==-1);C(service->setStatsCounterset(session,123,1).exception==-1);C(out==std::vector<int64_t>{777}&&ioCount==n);}
 android::IPCThreadState::uid=1000;
 C(service->readStats(session+1,0,0,0,&out).code==ESTALE);C(service->swapStats(session+1,0,1,&out).code==ESTALE);C(service->acknowledgeStats(session+1,1,7).code==ESTALE);C(service->setStatsCounterset(session+1,123,1).code==ESTALE);
 C(service->readStats(session,0,0,0,&out).code==EAGAIN&&out==std::vector<int64_t>{777});C(service->swapStats(session,0,1,&out).code==EAGAIN);C(service->acknowledgeStats(session,1,7).code==EAGAIN);C(service->setStatsCounterset(session,123,1).code==EAGAIN);
 for(int kind:{-1,4})C(service->readStats(session,kind,0,0,&out).code==EINVAL);
 for(int bank:{-1,2}){C(service->readStats(session,1,bank,7,&out).code==EINVAL);C(service->swapStats(session,bank,1,&out).code==EINVAL);C(service->acknowledgeStats(session,bank,7).code==EINVAL);}
 C(service->readStats(session,1,1,0,&out).code==EINVAL);C(service->readStats(session,0,1,0,&out).code==EINVAL);C(service->readStats(session,2,0,7,&out).code==EINVAL);C(service->readStats(session,3,0,0,nullptr).code==EINVAL);C(service->swapStats(session,0,0,&out).code==EINVAL);C(service->swapStats(session,0,1,nullptr).code==EINVAL);C(service->acknowledgeStats(session,0,0).code==EINVAL);C(service->setStatsCounterset(session,-1,0).code==EINVAL);C(service->setStatsCounterset(session,123,-1).code==EINVAL);C(service->setStatsCounterset(session,123,2).code==EINVAL);
 send(*service,session,0,image());C(service->commitFrame(session,&g).isOk()&&g>0&&!held);
 C(service->readStats(session,0,0,0,&out).isOk());C(out.size()==15&&out[0]==1&&out[1]==0&&out[2]==0&&out[3]==1&&out.back()==-1);
 appRead=false;C(service->readStats(session,1,1,7,&out).isOk());C(out==std::vector<int64_t>({1,1,1,7,-1,-1,1,1,7,1,17,3,4,5,6}));
 appRead=true;C(service->readStats(session,2,0,0,&out).isOk());C(out==std::vector<int64_t>({1,2,-1,-1,1,1,3,4,5,6}));
 C(service->readStats(session,3,0,0,&out).isOk());C(out==std::vector<int64_t>({1,3,-1,-1,1,17,-1,1,2,3}));
 largeStatsRows=5000;appRead=false;C(service->readStats(session,1,1,7,&out).isOk());C(out.size()==40007&&out[6]==5000&&out[7+8*4999]==5000&&out.back()==6);
 largeStatsRows=10000;appRead=true;C(service->readStats(session,2,0,0,&out).isOk());C(out.size()==50005&&out[4]==10000&&out[5+5*9999]==10000&&out.back()==6);
 largeStatsRows=0;
 C(service->swapStats(session,0,1,&out).isOk());C(out==std::vector<int64_t>({1,2,0,1}));C(service->acknowledgeStats(session,1,7).isOk());C(service->setStatsCounterset(session,123,1).isOk());C(service->setStatsCounterset(session,123,0).isOk());
 C(service->closeSession(client).isOk()&&held);C(service->readStats(session,0,0,0,&out).code==ESTALE);
 }
 for(unsigned op=0;op<4;++op){resetActive();AccountingCombined kernel;P owner(kernel);C(!owner.startWithAccounting(accountingProgram));auto service=sp<Service>::make(owner);auto client=sp<IBinder>::make();int64_t session=0,g=0;C(service->openSession(client,1,&session).isOk());send(*service,session,0,image());C(service->commitFrame(session,&g).isOk());std::vector<int64_t>out{777};packetError=1;packetErrno=EIO;auto before=packetCalls;
 android::binder::Status r;switch(op){case 0:r=service->readStats(session,0,0,0,&out);break;case 1:r=service->swapStats(session,0,1,&out);break;case 2:r=service->acknowledgeStats(session,1,7);break;default:r=service->setStatsCounterset(session,123,1);}
 C(r.code==EIO&&held&&files.empty());C(out==std::vector<int64_t>{777}&&packetCalls==before+1);C(service->readStats(session,0,0,0,&out).code==EAGAIN);
 }
 C(files.empty()&&held);printf("stats_rpc_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
