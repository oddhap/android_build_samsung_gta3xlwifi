#pragma once
#include <string>
#include <cstdarg>
#include <cstdio>
namespace android::base {
inline void StringAppendF(std::string* out, const char* format, ...) {
    char b[4096]; va_list args; va_start(args, format);
    int len = vsnprintf(b, sizeof(b), format, args); va_end(args);
    if (len < 0 || len >= static_cast<int>(sizeof(b))) throw "truncated command";
    *out += b;
}
}
