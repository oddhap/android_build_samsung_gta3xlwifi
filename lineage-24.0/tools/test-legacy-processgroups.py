#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host tests of the actual v1 cleanup algorithm, with injected cgroup syscalls.

This exercises error/retry semantics, NOT real Android cgroups or a device.
Run: python3 test-legacy-processgroups.py TOP
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def function(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        if text[end] == '{':
            depth += 1
        elif text[end] == '}':
            depth -= 1
        end += 1
    return text[start:end]


def main(top):
    process = (top / 'system/core/libprocessgroup/processgroup.cpp').read_text()
    profiles = (top / 'system/core/libprocessgroup/task_profiles.cpp').read_text()
    cleanup = function(process, 'static int KillLegacyProcessGroup(')
    paths = function(profiles, 'static bool isSystemApp(') + '\n' + function(
        profiles, 'std::string ConvertUidToPath(')
    source = r'''
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <deque>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
using namespace std::chrono_literals;
static constexpr uid_t AID_APP_START = 10000;
namespace android::libprocessgroup_flags {
    bool cgroup_v2_sys_app_isolation() { return true; }
}
static std::string StringPrintf(const char* fmt, ...) {
    char buf[256]; va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap); return buf;
}
static bool hierarchy, memcg, signal_ok;
static int signals;
static std::deque<int> results;
static std::vector<std::string> removed;
static bool GetProcessGroupHierarchyPath(std::string* path) {
    *path = "/acct"; return hierarchy;
}
static bool CgroupGetMemcgAppsPath(std::string* path) {
    *path = "/dev/memcg/apps"; return true;
}
static bool isMemoryCgroupSupported() { return memcg; }
static bool UsePerAppMemcg() { return memcg; }
static bool sendSignalToProcessGroup(uid_t, pid_t, int) {
    ++signals; errno = signal_ok ? 0 : EACCES; return signal_ok;
}
static int RemoveCgroup(const char* path, uid_t, pid_t, bool v2) {
    assert(!v2);  // v1 must never use the new Android 16 v2 path layout.
    removed.emplace_back(path);
    assert(!results.empty());
    const int err = results.front(); results.pop_front(); errno = err;
    return err ? -1 : 0;
}
template <typename T> static auto toMillisec(T duration) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration);
}
''' + paths + '\n' + cleanup + r'''
static void reset(std::initializer_list<int> errors, bool memory = false) {
    results = errors; removed.clear(); hierarchy = true; memcg = memory;
    signal_ok = true; signals = 0; errno = 0;
}
static int run(bool once = false, std::chrono::milliseconds timeout = 100ms) {
    return KillLegacyProcessGroup(10001, 1234, 9, once,
                                  std::chrono::steady_clock::now() + timeout);
}
int main() {
    reset({0}); assert(run() == 0); assert(signals == 1);
    reset({EBUSY, 0}); assert(run() == 0); assert(signals == 2);
    reset({EBUSY}); assert(run(true) == -1); assert(errno == EBUSY);
    reset({EBUSY}); assert(run(false, 0ms) == -1); assert(errno == EBUSY);
    reset({EACCES}); assert(run() == -1); assert(errno == EACCES); assert(signals == 1);
    reset({}); signal_ok = false; assert(run() == -1); assert(errno == EACCES);
    assert(removed.empty());
    reset({}); hierarchy = false; assert(run() == -ENODEV); assert(signals == 0);
    reset({0, EBUSY, 0, 0}, true); assert(run() == 0); assert(signals == 2);
    assert(removed[0] == "/acct" && removed[1] == "/dev/memcg/apps");
    reset({EBUSY, 0}, true); assert(run(true) == -1); assert(errno == EBUSY);
    reset({0, EACCES}, true); assert(run() == -1); assert(errno == EACCES);
    assert(ConvertUidToPath("/acct", 10001, false) == "/acct/uid_10001");
    assert(ConvertUidToPath("/acct", 1000, false) == "/acct/uid_1000");
    assert(ConvertUidToPath("/sys/fs/cgroup", 10001, true) ==
           "/sys/fs/cgroup/apps/uid_10001");
    assert(ConvertUidToPath("/sys/fs/cgroup", 1000, true) ==
           "/sys/fs/cgroup/system/uid_1000");
    puts("PASS: 10 v1 cleanup scenarios and 4 v1/v2 path assertions");
}
'''
    with tempfile.TemporaryDirectory(prefix='gta3xlwifi-cgroup-test-') as temp:
        path = Path(temp)
        (path / 'test.cpp').write_text(source)
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++20', '-Wall', '-Wextra',
                        '-Werror', '-pthread', str(path / 'test.cpp'), '-o', str(path / 'test')],
                       check=True)
        subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(Path(sys.argv[1]))
