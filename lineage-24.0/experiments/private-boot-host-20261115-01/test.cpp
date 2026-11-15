
#include "NetdUpdatablePublic.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
struct Exit{int code;};[[noreturn]]void testExit(int n){throw Exit{n};}
#define exit testExit
#define ALOGE(...) ((void)0)
struct Fixture{bool legacy=false,cgroup=true,netlink=true;int bpf=0,library=0,tagStart=0,firstVerify=0,secondVerify=0,nmStart=0,dns=0;unsigned checks=0,tags=0,untags=0,tagStops=0,ownerStops=0;std::vector<std::string> events;} f;
struct Logger{void info(const char*){}}gLog;
constexpr const char*CGROUPV2_HIERARCHY_NAME="v2";
bool CgroupGetControllerPath(const char*,std::string*out){f.events.push_back("cgroup");*out="/real/cgroup";return f.cgroup;}
int libnetd_updatable_init(const char*p){assert(!strcmp(p,"/real/cgroup")||!strcmp(p,"/sys/fs/cgroup"));f.events.push_back("bpf");return f.bpf;}
static NetdGta3xlwifiCallbacks installed{};
int resolv_set_gta3xlwifi_policy(int (*callback)(uid_t,bool)){f.events.push_back("dns-register");assert(callback);assert(callback(UINT32_MAX,false)==-EINVAL);assert(callback(10001,false)==-EAGAIN);return f.dns;}
int libnetd_updatable_init_gta3xlwifi(const NetdGta3xlwifiCallbacks*c){assert(c&&c->version==1&&c->size==sizeof(*c));f.events.push_back("library");if(f.library)return f.library;int result=c->initialize_held();if(!result)installed=*c;return result;}
struct NetlinkManager{static NetlinkManager*Instance(){f.events.push_back("netlink-instance");static NetlinkManager n;return f.netlink?&n:nullptr;}int start(){f.events.push_back("netlink-start");return f.nmStart;}};
namespace android::base{bool GetBoolProperty(const char*p,bool fallback){assert(!strcmp(p,"ro.gta3xlwifi.legacy_networking")&&!fallback);return f.legacy;}}
namespace android::net::gta3xlwifi{
struct QtaguidTransport{bool live=false;int start(){f.events.push_back("tag-start");if(!f.tagStart)live=true;return f.tagStart;}void stop(){live=false;++f.tagStops;f.events.push_back("tag-stop");}};
struct SocketPolicyProjection{int isNetworkingBlocked(int32_t uid,bool metered){assert(uid==10001&&!metered);return -EAGAIN;}int verifyHeldProviderStartup(){f.events.push_back("verify");return ++f.checks==1?f.firstVerify:f.secondVerify;}void stop(){++f.ownerStops;f.events.push_back("owner-stop");}int tagSocket(QtaguidTransport&t,int fd,uint32_t value,int32_t charge,int32_t real){assert(t.live&&fd==9&&value==7&&charge==123&&real==456);++f.tags;return -EAGAIN;}int untagSocket(QtaguidTransport&t,int fd){assert(t.live&&fd==9);++f.untags;return -EAGAIN;}};
}
namespace android::net{struct Controllers{gta3xlwifi::SocketPolicyProjection policy;void init(){f.events.push_back("controllers");}gta3xlwifi::SocketPolicyProjection*gta3xlwifiPolicy(){return f.legacy?&policy:nullptr;}};}
namespace android::net::gta3xlwifi {
namespace {
QtaguidTransport transport;
SocketPolicyProjection* owner = nullptr;
int initialize() {
    if (!owner) return -ENOTCONN;
    int result = owner->verifyHeldProviderStartup();
    if (!result) result = transport.start();
    if (!result) result = owner->verifyHeldProviderStartup();
    return result;
}
int tag(int fd, uint32_t value, uid_t chargeUid, uid_t realUid) {
    if (chargeUid > INT_MAX || realUid > INT_MAX) return -EINVAL;
    return owner ? owner->tagSocket(transport, fd, value, chargeUid, realUid) : -ENOTCONN;
}
int blocked(uid_t uid, bool metered) {
    if (uid > INT_MAX) return -EINVAL;
    return owner ? owner->isNetworkingBlocked(uid, metered) : -ENOTCONN;
}
int untag(int fd) {
    return owner ? owner->untagSocket(transport, fd) : -ENOTCONN;
}
}  // namespace
int initializeHeldProvider(Controllers& controllers) {
    // Main-thread only, before Netlink/Binder listeners. Successful publication
    // of callbacks fixes owner/transport identity for the process lifetime.
    if (owner) return -EALREADY;
    owner = controllers.gta3xlwifiPolicy();
    if (!owner) return -EOPNOTSUPP;
    const NetdGta3xlwifiCallbacks callbacks{1, sizeof(NetdGta3xlwifiCallbacks),
                                         initialize, tag, untag};
    int result = libnetd_updatable_init_gta3xlwifi(&callbacks);
    if (!result) result = resolv_set_gta3xlwifi_policy(blocked);
    if (result) {
        transport.stop();
        owner->stop();
        owner = nullptr;
    }
    return result;
}
int checkHeldProviderStartup(Controllers& controllers) {
    const int result = initializeHeldProvider(controllers);
    if (result) return result;
    // initializeHeldProvider has verified HOLD on both sides of transport start.
    // No framework policy has been published; closing the lease rearms HOLD.
    transport.stop();
    owner->stop();
    owner = nullptr;
    return 0;
}
}  // namespace android::net::gta3xlwifi

android::net::Controllers*gCtls=nullptr;
static int preflight(int argc,const char*argv[]){
    if ((argc == 2) && !strcmp(argv[1], "oneshot")) {
        setenv("NETD_ONESHOT", "1", 1);
        if (android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
            android::net::Controllers controllers;
            controllers.init();
            const int result = android::net::gta3xlwifi::checkHeldProviderStartup(controllers);
            if (result) ALOGE("Private held preflight failed: %d", result);
            return result ? 1 : 0;
        }
        return libnetd_updatable_init("/sys/fs/cgroup");
    }
return 88;
}
static void startup(){
    const bool legacy = android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false);
    if (!legacy) {
        std::string cg2_path;
        if (!CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &cg2_path)) {
            ALOGE("Failed to find cgroup v2 root %s", strerror(errno));
            exit(1);
        }

        if (libnetd_updatable_init(cg2_path.c_str())) {
            ALOGE("libnetd_updatable_init failed");
            exit(1);
        }
        gLog.info("libnetd_updatable_init success");

    }

    NetlinkManager *nm = NetlinkManager::Instance();
    if (nm == nullptr) {
        ALOGE("Unable to create NetlinkManager");
        exit(1);
    };
    gLog.info("NetlinkManager instanced");

    gCtls = new android::net::Controllers();
    gCtls->init();
    if (legacy) {
        const int result = android::net::gta3xlwifi::initializeHeldProvider(*gCtls);
        if (result) {
            ALOGE("Private held provider initialization failed: %d", result);
            exit(1);
        }
        gLog.info("Private transport initialized; complete framework policy still required");
    }

    if (nm->start()) {
        ALOGE("Unable to start NetlinkManager (%s)", strerror(errno));
        exit(1);
    }


}
static void reset(){using namespace android::net::gta3xlwifi;owner=nullptr;transport.live=false;delete gCtls;gCtls=nullptr;installed={};f=Fixture{};}
int main(){unsigned cases=0;using namespace android::net::gta3xlwifi;
 for(bool legacy:{false,true})for(unsigned fault=0;fault<11;fault++){
  reset();f.legacy=legacy;int expected=0;
  if(fault==1&&!legacy){f.cgroup=false;expected=1;}
  if(fault==2&&!legacy){f.bpf=-EIO;expected=1;}
  if(fault==3){f.netlink=false;expected=1;}
  if(fault==4&&legacy){f.library=-EOPNOTSUPP;expected=1;}
  if(fault==5&&legacy){f.firstVerify=-EIO;expected=1;}
  if(fault==6&&legacy){f.tagStart=-EBUSY;expected=1;}
  if(fault==7&&legacy){f.secondVerify=-EPROTO;expected=1;}
  if(fault==8){f.nmStart=-EIO;expected=1;}
  if(fault==10&&legacy){f.dns=-EIO;expected=1;}
  int result=0;try{startup();}catch(Exit e){result=e.code;}assert(result==expected);
  if(!legacy){assert(!owner&&!transport.live&&!installed.initialize_held&&!f.checks);assert(f.events[0]=="cgroup");}
  else{for(auto&e:f.events)assert(e!="bpf"&&e!="cgroup");assert(f.events[0]=="netlink-instance");if((fault>=4&&fault<=7)||fault==10)assert(!owner&&!transport.live&&f.tagStops==1&&f.ownerStops==1);if(!expected){assert((f.events==std::vector<std::string>{"netlink-instance","controllers","library","verify","tag-start","verify","dns-register","netlink-start"}));auto count=f.events.size();assert(initializeHeldProvider(*gCtls)==-EALREADY&&f.events.size()==count);assert(installed.tag_socket(9,7,123,456)==-EAGAIN&&f.tags==1);assert(installed.untag_socket(9)==-EAGAIN&&f.untags==1);assert(installed.tag_socket(9,7,UINT32_MAX,456)==-EINVAL&&f.tags==1);assert(installed.tag_socket(9,7,123,UINT32_MAX)==-EINVAL&&f.tags==1);}}
  ++cases;
 }
 const char*args[]={"netd","oneshot"};
 for(bool legacy:{false,true})for(unsigned fault=0;fault<7;++fault){
  reset();f.legacy=legacy;
  if(fault==1)f.library=-EIO;
  if(fault==2)f.firstVerify=-EIO;
  if(fault==3)f.tagStart=-EIO;
  if(fault==4)f.secondVerify=-EIO;
  if(fault==5)f.dns=-EIO;
  if(fault==6)f.bpf=-EIO;
  int result=preflight(2,args);
  assert(result==(legacy?((fault>=1&&fault<=5)?1:0):(fault==6?-EIO:0)));
  assert(!owner&&!transport.live&&!f.nmStart);
  for(const auto&e:f.events)assert(e!="netlink-instance"&&e!="netlink-start");
  if(legacy){assert(f.events.front()=="controllers");assert(f.ownerStops==1&&f.tagStops==1);}
  else assert(f.events==std::vector<std::string>{"bpf"});
  ++cases;
 }
 reset();assert(preflight(1,args)==88&&f.events.empty());++cases;
 reset();android::net::Controllers c;assert(initializeHeldProvider(c)==-EOPNOTSUPP&&!owner&&!transport.live);++cases;reset();printf("passed_cases=%u\n",cases);
}
