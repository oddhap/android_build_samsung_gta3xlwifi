
#include "NetdUpdatablePublic.h"
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <vector>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
struct Logger{template<class T>Logger&operator<<(const T&){return *this;}};
#define LOG(x) Logger{}
static unsigned bpfInit,bpfTags,bpfUntags;static bool bpfFail;
namespace android::base{void InitLogging(void*){}template<class T>struct Result{bool ok()const{return !bpfFail;}const char* error()const{return "BPF failure";}};}
Logger&operator<<(Logger&l,const char*){return l;}
namespace android::net{struct BpfHandler{android::base::Result<void>init(const char*p){assert(p&&*p);++bpfInit;return {};}int tagSocket(int fd,uint32_t tag,uid_t charge,uid_t real){assert(fd==19&&tag==UINT32_MAX&&charge==123&&real==456);++bpfTags;return -EPERM;}int untagSocket(int fd){assert(fd==19);++bpfUntags;return -ENOENT;}};}
static android::net::BpfHandler sBpfHandler;
namespace {
std::mutex sInitMutex;
bool sInitialized = false;
std::atomic<bool> sPrivateProvider{false};
NetdGta3xlwifiCallbacks sCallbacks{};
}

int libnetd_updatable_init(const char* cg2_path) {
    std::lock_guard<std::mutex> lock(sInitMutex);
    if (sPrivateProvider.load(std::memory_order_acquire)) return -EBUSY;
    android::base::InitLogging(/*argv=*/nullptr);
    LOG(INFO) << __func__ << ": Initializing";

    android::base::Result<void> ret = sBpfHandler.init(cg2_path);
    if (!ret.ok()) {
        LOG(ERROR) << __func__ << ": Failed: " << ret.error();
        abort();
    }
    sInitialized = true;
    return 0;
}

int libnetd_updatable_tagSocket(int sockFd, uint32_t tag, uid_t chargeUid, uid_t realUid) {
    if (sPrivateProvider.load(std::memory_order_acquire))
        return sCallbacks.tag_socket(sockFd, tag, chargeUid, realUid);
    return sBpfHandler.tagSocket(sockFd, tag, chargeUid, realUid);
}

int libnetd_updatable_untagSocket(int sockFd) {
    if (sPrivateProvider.load(std::memory_order_acquire))
        return sCallbacks.untag_socket(sockFd);
    return sBpfHandler.untagSocket(sockFd);
}

int libnetd_updatable_init_gta3xlwifi(const NetdGta3xlwifiCallbacks* callbacks) {
    if (!callbacks || callbacks->version != 1 || callbacks->size != sizeof(*callbacks) ||
        !callbacks->initialize_held || !callbacks->tag_socket || !callbacks->untag_socket)
        return -EINVAL;
    std::lock_guard<std::mutex> lock(sInitMutex);
    if (sInitialized) return -EALREADY;
    const NetdGta3xlwifiCallbacks next = *callbacks;
    const int result = next.initialize_held();
    if (result) return result < 0 ? result : -EPROTO;
    sCallbacks = next;
    sInitialized = true;
    sPrivateProvider.store(true, std::memory_order_release);
    return 0;  // Held transport initialized, policy still unpublished.
}

static unsigned cases,initCalls;static int initResult;static std::atomic<unsigned> tagCalls,untagCalls;
static NetdGta3xlwifiCallbacks*mutate;
static int initialize(){++initCalls;if(mutate){mutate->tag_socket=nullptr;mutate->size=0;}return initResult;}
static int tag(int fd,uint32_t value,uid_t charge,uid_t real){assert(fd==19&&value==UINT32_MAX&&charge==123&&real==456);++tagCalls;return -77;}
static int untag(int fd){assert(fd==19);++untagCalls;return -88;}
static NetdGta3xlwifiCallbacks valid(){return {1,sizeof(NetdGta3xlwifiCallbacks),initialize,tag,untag};}
static void reset(){sPrivateProvider=false;sInitialized=false;sCallbacks={};bpfInit=bpfTags=bpfUntags=initCalls=0;bpfFail=false;initResult=0;tagCalls=0;untagCalls=0;mutate=nullptr;}
#define T(x) do{++cases;assert(x);}while(0)
int main(){
 reset();T(libnetd_updatable_tagSocket(19,UINT32_MAX,123,456)==-EPERM&&bpfTags==1);T(libnetd_updatable_untagSocket(19)==-ENOENT&&bpfUntags==1);T(libnetd_updatable_init("/real/cgroup/path")==0&&bpfInit==1);auto c=valid();T(libnetd_updatable_init_gta3xlwifi(&c)==-EALREADY&&!initCalls);T(libnetd_updatable_init("/real/cgroup/path")==0&&bpfInit==2);
 for(unsigned fault=0;fault<7;fault++){reset();c=valid();const NetdGta3xlwifiCallbacks*p=&c;switch(fault){case 0:p=nullptr;break;case 1:c.version=2;break;case 2:--c.size;break;case 3:++c.size;break;case 4:c.initialize_held=nullptr;break;case 5:c.tag_socket=nullptr;break;case 6:c.untag_socket=nullptr;break;}T(libnetd_updatable_init_gta3xlwifi(p)==-EINVAL&&!initCalls&&!sInitialized&&!sPrivateProvider&&!bpfInit);}
 for(int error:{-EIO,-ENODEV,-EOPNOTSUPP,1}){reset();c=valid();initResult=error;T(libnetd_updatable_init_gta3xlwifi(&c)==(error<0?error:-EPROTO)&&initCalls==1&&!sInitialized&&!sPrivateProvider&&!bpfInit);initResult=0;T(libnetd_updatable_init_gta3xlwifi(&c)==0&&initCalls==2&&sPrivateProvider&&!bpfInit);}
 reset();c=valid();mutate=&c;T(libnetd_updatable_init_gta3xlwifi(&c)==0&&sPrivateProvider&&!bpfInit&&initCalls==1);T(libnetd_updatable_tagSocket(19,UINT32_MAX,123,456)==-77&&tagCalls==1&&!bpfTags);T(libnetd_updatable_untagSocket(19)==-88&&untagCalls==1&&!bpfUntags);c=valid();T(libnetd_updatable_init_gta3xlwifi(&c)==-EALREADY&&initCalls==1);T(libnetd_updatable_init("/real/cgroup/path")==-EBUSY&&!bpfInit);
 std::vector<std::thread> workers;for(unsigned i=0;i<32;i++)workers.emplace_back([]{for(unsigned n=0;n<100;n++){assert(libnetd_updatable_tagSocket(19,UINT32_MAX,123,456)==-77);assert(libnetd_updatable_untagSocket(19)==-88);}});for(auto&t:workers)t.join();T(tagCalls==3201&&untagCalls==3201&&!bpfTags&&!bpfUntags);
 reset();c=valid();int results[2];std::thread one([&]{results[0]=libnetd_updatable_init_gta3xlwifi(&c);}),two([&]{results[1]=libnetd_updatable_init_gta3xlwifi(&c);});one.join();two.join();T((results[0]==0&&results[1]==-EALREADY)||(results[1]==0&&results[0]==-EALREADY));T(initCalls==1&&!bpfInit);
 reset();pid_t child=fork();assert(child>=0);if(!child){rlimit limit{0,0};setrlimit(RLIMIT_CORE,&limit);bpfFail=true;libnetd_updatable_init("/real/cgroup/path");_exit(99);}int status=0;assert(waitpid(child,&status,0)==child);T(WIFSIGNALED(status)&&WTERMSIG(status)==SIGABRT);
 printf("passed_cases=%u concurrent_callback_calls=6400\n",cases);
}
