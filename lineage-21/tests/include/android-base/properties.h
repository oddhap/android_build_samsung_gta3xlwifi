#pragma once
#include <string>
namespace android::base {
inline bool GetBoolProperty(const std::string&, bool) { return true; }
}
