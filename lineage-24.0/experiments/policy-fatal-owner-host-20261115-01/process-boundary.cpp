#include <atomic>
#include <cerrno>
#include <cassert>
#include "Gta3xlwifiPolicyFatal.h"
struct Termination{int code;};
[[noreturn]] void fixtureExit(int code){throw Termination{code};}
static unsigned logs;
#define ALOGE(...) (++logs)
#define _exit fixtureExit
namespace android::net::gta3xlwifi {
// Fatal owner recovery: no handler is installed by standalone fixtures.
namespace {
std::atomic<PolicyFatalHandler> policyFatalHandler{nullptr};
void dispatchPolicyFatal(int error) {
  if (auto handler=policyFatalHandler.load(std::memory_order_acquire)) handler(error);
}
}
int setPolicyFatalHandler(PolicyFatalHandler handler) {
  if(!handler)return -EINVAL;
  PolicyFatalHandler expected=nullptr;
  if(policyFatalHandler.compare_exchange_strong(expected,handler,
      std::memory_order_acq_rel,std::memory_order_acquire)||expected==handler)return 0;
  return -EALREADY;
}

}
[[noreturn]] void privatePolicyFatal(int error) {
    ALOGE("Private policy owner quarantined (%d); restarting netd via init",error);
    _exit(1);
}
int main(){using namespace android::net::gta3xlwifi;
 assert(!setPolicyFatalHandler(privatePolicyFatal));
 assert(!setPolicyFatalHandler(privatePolicyFatal));
 try{dispatchPolicyFatal(-EIO);assert(false);}catch(const Termination&e){assert(e.code==1&&logs==1);}
 return 0;
}
