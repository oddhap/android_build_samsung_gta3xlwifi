#!/usr/bin/env python3
"""Exercise the actual patched mount function with a read-only root syscall model.

This checks mount ordering and error propagation, not kernel/runtime behavior.
Run on the build VM after applying the platform patches.
"""
from pathlib import Path
import subprocess
import tempfile

source = Path('/srv/android/src/lineage-21.0/system/core/libprocessgroup/setup/cgroup_map_write.cpp').read_text()
start = source.index('static bool MountV1CgroupController(')
end = source.index('\nstatic bool SetupCgroup(', start)
function = source[start:end]
stub = r'''
#include <cstring>
#include <string>
#include <iostream>
#include <sys/mount.h>
#include <unistd.h>
#include <cstdlib>
#define LOG(x) std::cerr
#define PLOG(x) std::cerr
bool legacy, mounted, mount_fail, owner_fail, root_readonly;
int preparations, mounts, owners;
namespace format {
struct CgroupController {
    const char* controller_name;
    const char* name() const { return controller_name; }
    const char* path() const { return "/acct"; }
};
}
struct CgroupDescriptor {
    format::CgroupController value;
    const format::CgroupController* controller() const { return &value; }
    mode_t mode() const { return 0775; }
    std::string uid() const { return "system"; }
    std::string gid() const { return "system"; }
};
bool IsOptionalController(const format::CgroupController*) { return false; }
int MockAccess(const char*, int) { return legacy ? 0 : -1; }
bool Mkdir(const std::string&, mode_t mode, const std::string& uid, const std::string& gid) {
    ++preparations;
    if (mounted) std::abort();
    if (root_readonly && (!uid.empty() || !gid.empty() || mode != 0)) return false;
    return true;
}
int MockMount(const char*, const char*, const char*, unsigned long, const void*) {
    ++mounts;
    if (mount_fail) return -1;
    mounted = true;
    return 0;
}
bool ChangeDirModeAndOwner(const std::string&, mode_t mode, const std::string& uid,
                           const std::string& gid) {
    ++owners;
    if (!mounted || mode != 0775 || uid != "system" || gid != "system") std::abort();
    return !owner_fail;
}
#define access MockAccess
#define mount MockMount
'''
cases = r'''
void check(bool condition) { if (!condition) std::abort(); }
void reset(bool device, bool readonly, bool bad_mount = false, bool bad_owner = false) {
    legacy = device; root_readonly = readonly; mount_fail = bad_mount; owner_fail = bad_owner;
    mounted = false; preparations = mounts = owners = 0;
}
int main() {
    CgroupDescriptor cpuacct{{"cpuacct"}}, cpuset{{"cpuset"}};
    for (const auto& descriptor : {cpuacct, cpuset}) {
        reset(true, true);
        check(MountV1CgroupController(descriptor));
        check(preparations == 1 && mounts == 1 && owners == 1 && mounted);
    }
    reset(true, true, true);
    check(!MountV1CgroupController(cpuacct));
    check(mounts == 1 && owners == 0 && !mounted);
    reset(true, true, false, true);
    check(!MountV1CgroupController(cpuacct));
    check(mounts == 1 && owners == 1);
    reset(false, true);
    check(!MountV1CgroupController(cpuacct));
    check(mounts == 0 && owners == 0);
    reset(false, false);
    check(MountV1CgroupController(cpuacct));
    check(mounts == 1 && owners == 0);
    std::cout << "Mount ordering/error propagation checks passed (syscall model only).\n";
}
'''
with tempfile.TemporaryDirectory(prefix='cgroup-mount-order-') as directory:
    cpp = Path(directory) / 'check.cpp'
    binary = Path(directory) / 'check'
    cpp.write_text(stub + function + cases)
    subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror', str(cpp), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
