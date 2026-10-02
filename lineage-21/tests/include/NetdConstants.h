#pragma once
#include <string>
#include <mutex>
#include <cctype>
enum IptablesTarget { V4, V6, V4V6 };
int execIptablesRestore(IptablesTarget, const std::string&);
inline bool isIfaceName(const std::string& s) {
    if (s.empty() || s.size() >= 16) return false;
    for (unsigned char c : s) if (!isalnum(c) && c != '_' && c != '-' && c != '.') return false;
    return true;
}
namespace android::net {
extern std::mutex gBigNetdLock;
struct INetd {
    enum { PERMISSION_UNINSTALLED = -1, PERMISSION_INTERNET = 4, PERMISSION_UPDATE_DEVICE_STATS = 8 };
};
}
