#pragma once
#include <cstdint>
namespace android {class IPCThreadState{public:static inline thread_local uint32_t uid=1000;static IPCThreadState*self(){static thread_local IPCThreadState v;return &v;}uint32_t getCallingUid(){return uid;}};}
