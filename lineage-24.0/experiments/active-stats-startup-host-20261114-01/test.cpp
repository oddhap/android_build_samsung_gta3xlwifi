
#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cinttypes>
#include <map>
#include <memory>
#include <string>
#include <vector>
struct Exit{int code;};
struct Fixture{bool legacy=false,held=false;int lease=0,roots=0,flush=0,owner=0,route=0,xfrm=0;std::vector<std::string> events;std::string flushText;} f;
[[noreturn]] void testExit(int code){throw Exit{code};}
#define exit testExit
std::string Join(const std::vector<std::string>& v,char c){std::string s;for(auto&x:v){if(!s.empty())s+=c;s+=x;}return s;}
enum IptablesTarget{V4,V6,V4V6};
const std::string COMMIT_AND_CLOSE="COMMIT\n";
struct BandwidthController{
 std::map<std::string,int> mSharedQuotaIfaces{{"old",1}},mQuotaIfaces{{"old",1}};
 int64_t mGlobalAlertBytes=5,mSharedQuotaBytes=7;
 int prepareGta3xlwifiBandwidthControl();
 static std::vector<std::string> makeGta3xlwifiAccountingCommands(){f.events.push_back("factory");return {"REAL_FACTORY"};}
 int enableBandwidthControl(){assert(!f.legacy);f.events.push_back("stock");return f.flush;}
 static int iptablesRestoreFunction(IptablesTarget t,const std::string& text,std::string* out){assert(t==V4V6&&!out&&f.held);f.events.push_back("flush");f.flushText=text;return f.flush;}
};
static const std::vector<std::string> IPT_FLUSH_COMMANDS = {
        /*
         * Cleanup rules.
         * Should normally include bw_costly_<iface>, but we rely on the way they are setup
         * to allow coexistance.
         */
        "*filter",
        ":bw_INPUT -",
        ":bw_OUTPUT -",
        ":bw_FORWARD -",
        ":bw_happy_box -",
        ":bw_penalty_box -",
        ":bw_data_saver -",
        ":bw_costly_shared -",
        ":bw_global_alert -",
        "COMMIT",
        "*raw",
        ":bw_raw_PREROUTING -",
        "COMMIT",
        "*mangle",
        ":bw_mangle_POSTROUTING -",
        COMMIT_AND_CLOSE};
int BandwidthController::prepareGta3xlwifiBandwidthControl() {
    const int result = iptablesRestoreFunction(V4V6, Join(IPT_FLUSH_COMMANDS, '\n'), nullptr);
    if (result) return result;
    mSharedQuotaIfaces.clear();
    mQuotaIfaces.clear();
    mGlobalAlertBytes = 0;
    mSharedQuotaBytes = 0;
    return 0;
}
namespace android::base{bool GetBoolProperty(const char*name,bool fallback){assert(!strcmp(name,"ro.gta3xlwifi.legacy_networking")&&!fallback);return f.legacy;}}
namespace android::net{
struct Log{template<class...T>void error(const char*,T...){ }template<class...T>void info(const char*,T...){ }} gLog;
struct Stopwatch{long getTimeAndResetUs(){return 0;}};
struct Status{int value;};bool isOk(Status s){return s.value==0;}
namespace netdutils{using Status=android::net::Status;std::string toString(Status){return "failure";}}
struct RouteController{static int Init(int id){assert(id==99);f.events.push_back("route");return f.route;}};
struct NetworkController{static constexpr int LOCAL_NET_ID=99;};
struct XfrmController{static Status Init(){f.events.push_back("xfrm");return {f.xfrm};}};
namespace gta3xlwifi{
struct SocketPolicyProjection{
 explicit SocketPolicyProjection(int&){f.events.push_back("construct");}
 int prepareForControllerStartup(){f.events.push_back("lease");if(!f.lease)f.held=true;return f.lease;}
 int startWithAccounting(const std::vector<std::string>& p){assert(f.held&&p==std::vector<std::string>{"REAL_FACTORY"});f.events.push_back("owner");return f.owner;}
};}
std::unique_ptr<gta3xlwifi::SocketPolicyProjection> gta3xlwifiPolicyOwner;
struct Controllers{BandwidthController bandwidthCtrl;int iptablesRestoreCtrl=0;void init();gta3xlwifi::SocketPolicyProjection* gta3xlwifiPolicy()const;
 int initIptablesRules(){assert(!f.legacy||f.held);f.events.push_back("roots");return f.roots;}};
gta3xlwifi::SocketPolicyProjection* Controllers::gta3xlwifiPolicy() const {
    return gta3xlwifiPolicyOwner.get();
}
void Controllers::init() {
    const bool legacy = android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false);
    if (legacy) {
        if (gta3xlwifiPolicyOwner) {
            gLog.error("Private policy owner already initialized");
            exit(5);
        }
        gta3xlwifiPolicyOwner = std::make_unique<gta3xlwifi::SocketPolicyProjection>(
                iptablesRestoreCtrl);
        if (int ret = gta3xlwifiPolicyOwner->prepareForControllerStartup()) {
            gLog.error("Failed to acquire held private policy lease (%s)", strerror(-ret));
            exit(5);
        }
    }
    if (initIptablesRules()) {
        gLog.error("Failed to initialize iptables rules");
        exit(1);
    }
    Stopwatch s;

    const int bandwidthResult = legacy ? bandwidthCtrl.prepareGta3xlwifiBandwidthControl()
                                       : bandwidthCtrl.enableBandwidthControl();
    if (int ret = bandwidthResult) {
        gLog.error("Failed to initialize BandwidthController (%s)", strerror(-ret));
        // A failure to init almost definitely means that iptables failed to load
        // our static ruleset, which then basically means network accounting will not work.
        // As such simply exit netd.  This may crash loop the system, but by failing
        // to bootup we will trigger rollback and thus this offers us protection against
        // a mainline update breaking things.
        exit(2);
    }
    gLog.info("Enabling bandwidth control: %" PRId64 "us", s.getTimeAndResetUs());

    if (legacy) {
        const auto program = BandwidthController::makeGta3xlwifiAccountingCommands();
        if (int ret = gta3xlwifiPolicyOwner->startWithAccounting(program)) {
            gLog.error("Failed to verify held private accounting startup (%s)", strerror(-ret));
            exit(6);
        }
        // Remains held and unpublished until a complete explicit framework frame.
    }

    if (int ret = RouteController::Init(NetworkController::LOCAL_NET_ID)) {
        gLog.error("Failed to initialize RouteController (%s)", strerror(-ret));
        exit(3);
    }
    gLog.info("Initializing RouteController: %" PRId64 "us", s.getTimeAndResetUs());

    netdutils::Status xStatus = XfrmController::Init();
    if (!isOk(xStatus)) {
        gLog.error("Failed to initialize XfrmController (%s)", netdutils::toString(xStatus).c_str());
        exit(4);
    };
    gLog.info("Initializing XfrmController: %" PRId64 "us", s.getTimeAndResetUs());
}
}
int main(){using namespace android::net;unsigned cases=0;
 for(bool legacy:{false,true})for(int stage=0;stage<=6;stage++)for(int error:{-EIO,1}){
  f=Fixture{};f.legacy=legacy;gta3xlwifiPolicyOwner.reset();int expected=0;
  if(stage==1&&legacy){f.lease=error;expected=5;}
  if(stage==2){f.roots=error;expected=1;}
  if(stage==3){f.flush=error;expected=2;}
  if(stage==4&&legacy){f.owner=error;expected=6;}
  if(stage==5){f.route=error;expected=3;}
  if(stage==6){f.xfrm=error;expected=4;}
  Controllers c;int status=0;try{c.init();}catch(Exit e){status=e.code;}assert(status==expected);
  std::vector<std::string> wanted;
  if(legacy){wanted={"construct","lease"};if(expected==5)goto compare;}
  wanted.push_back("roots");if(expected==1)goto compare;
  wanted.push_back(legacy?"flush":"stock");if(expected==2)goto compare;
  if(legacy){wanted.push_back("factory");wanted.push_back("owner");if(expected==6)goto compare;}
  wanted.push_back("route");if(expected==3)goto compare;wanted.push_back("xfrm");
 compare:
  assert(f.events==wanted);assert(bool(c.gta3xlwifiPolicy())==legacy);if(legacy&&expected!=5)assert(f.held);
  if(legacy&&stage>=3){if(expected==2)assert(c.bandwidthCtrl.mGlobalAlertBytes==5&&c.bandwidthCtrl.mSharedQuotaBytes==7&&!c.bandwidthCtrl.mSharedQuotaIfaces.empty());else assert(c.bandwidthCtrl.mGlobalAlertBytes==0&&c.bandwidthCtrl.mSharedQuotaBytes==0&&c.bandwidthCtrl.mQuotaIfaces.empty());}
  if(legacy&&expected==0){auto count=f.events.size();try{c.init();assert(false);}catch(Exit e){assert(e.code==5);}assert(f.events.size()==count&&f.held);}
  ++cases;
 }
 f=Fixture{};f.held=true;BandwidthController b;assert(b.prepareGta3xlwifiBandwidthControl()==0);assert(f.flushText==Join(IPT_FLUSH_COMMANDS,'\n'));assert(f.flushText.find("bpf")==std::string::npos);++cases;
 printf("passed_cases=%u\n",cases);
}
