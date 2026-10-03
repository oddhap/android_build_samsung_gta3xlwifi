#!/usr/bin/env python3
"""Apply the SM-T510 cgroup v1 lifecycle integration to pinned Android 14."""
from pathlib import Path

top = Path('/srv/android/src/lineage-21.0/system/core/libprocessgroup')

def edit(name, before, after):
    path = top / name
    data = path.read_text()
    if after in data:
        return
    if data.count(before) != 1:
        raise SystemExit(f'Unexpected source anchor: {name}: {before[:70]}')
    path.write_text(data.replace(before, after, 1))

# The immutable product file selects this backend, without changing other
# devices or pretending that cgroup v2 was mounted successfully.
edit('setup/cgroup_map_write.cpp', '    return true;\n}\n\n// To avoid issues in sdk_mac build', '''    const char* legacy = "/system/etc/cgroups.gta3xlwifi.json";
    if (access(legacy, F_OK) == 0 && !ReadDescriptorsFromFile(legacy, descriptors)) {
        return false;
    }
    return true;
}

// To avoid issues in sdk_mac build''')
edit('setup/cgroup_map_write.cpp', '    // setup cgroups\n    for (auto& [name, descriptor] : descriptors) {', '''    // The SM-T510 kernel has cgroup v1, with no blkio/schedtune controllers.
    const bool legacy = access("/system/etc/cgroups.gta3xlwifi.json", F_OK) == 0;
    // setup cgroups
    for (auto& [name, descriptor] : descriptors) {
        if (legacy && (descriptor.controller()->version() == 2 ||
                       name == "blkio" || name == "schedtune")) {
            descriptor.set_mounted(false);
            continue;
        }''')
edit('setup/cgroup_map_write.cpp', '    return true;\n}\n\nstatic bool SetupCgroup(const CgroupDescriptor& descriptor)', '''    // Ownership set before mount belongs to the underlying mountpoint, not
    // the new controller filesystem. Match the v2 setup's post-mount ownership.
    if (access("/system/etc/cgroups.gta3xlwifi.json", F_OK) == 0 &&
        !ChangeDirModeAndOwner(controller->path(), descriptor.mode(), descriptor.uid(),
                               descriptor.gid())) {
        return false;
    }
    return true;
}

static bool SetupCgroup(const CgroupDescriptor& descriptor)''')
edit('task_profiles.cpp', '\n}\n\nbool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name)', '''
    const char* legacy = "/system/etc/task_profiles.gta3xlwifi.json";
    if (access(legacy, F_OK) == 0 && !Load(CgroupMap::GetInstance(), legacy)) {
        LOG(ERROR) << "Failed to load SM-T510 cgroup v1 task profiles";
    }
}

bool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name)''')

edit('processgroup.cpp', 'static std::string ConvertUidToPath', '''static bool LegacyGta3xlwifiProcessGroups() {
    static const bool legacy = access("/system/etc/cgroups.gta3xlwifi.json", F_OK) == 0;
    return legacy;
}

static bool GetProcessGroupHierarchyPath(std::string* path) {
    return CgroupGetControllerPath(LegacyGta3xlwifiProcessGroups() ? "cpuacct"
                                                                : CGROUPV2_HIERARCHY_NAME, path);
}

static std::string ConvertUidToPath''')
path = top / 'processgroup.cpp'
data = path.read_text()
for variable in ('cg_kill', 'path', 'hierarchy_root_path', 'cgroup'):
    data = data.replace(f'CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &{variable})',
                        f'GetProcessGroupHierarchyPath(&{variable})')
path.write_text(data)
edit('processgroup.cpp', 'static bool CgroupKillAvailable() {', '''static bool CgroupKillAvailable() {
    if (LegacyGta3xlwifiProcessGroups()) return false;''')
edit('processgroup.cpp', '        GetProcessGroupHierarchyPath(&hierarchy_root_path);\n        cgroup_v2_path', '''        if (!GetProcessGroupHierarchyPath(&hierarchy_root_path)) {
            kill(-initialPid, signal);
            errno = ENODEV;
            return false;
        }
        cgroup_v2_path''')
edit('processgroup.cpp', '    std::string cgroup;\n    GetProcessGroupHierarchyPath(&cgroup);\n    return createProcessGroupInternal(uid, initialPid, cgroup, true);', '''    std::string cgroup;
    if (!GetProcessGroupHierarchyPath(&cgroup)) return -ENODEV;
    return createProcessGroupInternal(uid, initialPid, cgroup,
                                      !LegacyGta3xlwifiProcessGroups());''')
edit('processgroup.cpp', '// The default timeout of 2200ms', '''// cgroup v1 has cgroup.procs and EBUSY directory removal, but no cgroup.events.
// Keep real signaling and bounded cleanup rather than reporting a false success.
static int KillLegacyProcessGroup(uid_t uid, pid_t pid, int signal, bool once,
                                  std::chrono::steady_clock::time_point until) {
    std::string root;
    if (!GetProcessGroupHierarchyPath(&root)) { errno = ENODEV; return -1; }
    int ret;
    do {
        if (!sendSignalToProcessGroup(uid, pid, signal) && errno != ENOENT) return -1;
        ret = RemoveCgroup(root.c_str(), uid, pid);
        if (ret && errno != EBUSY) return ret;
        const int group_errno = errno;
        if (isMemoryCgroupSupported() && UsePerAppMemcg()) {
            std::string memory;
            if (CgroupGetMemcgAppsPath(&memory) && memory != root) {
                const int memory_ret = RemoveCgroup(memory.c_str(), uid, pid);
                if (memory_ret && errno != EBUSY) return memory_ret;
                if (memory_ret) ret = memory_ret;
                else if (ret) errno = group_errno;
            }
        }
        if (!ret || once) break;
        auto now = std::chrono::steady_clock::now();
        if (now >= until) break;
        std::this_thread::sleep_for(std::min(5ms, toMillisec(until - now)));
    } while (true);
    return ret;
}

// The default timeout of 2200ms''')
edit('processgroup.cpp', '    if (!CgroupsAvailable() || !signal_ret) return signal_ret ? 0 : -1;\n', '''    if (!CgroupsAvailable() || !signal_ret) return signal_ret ? 0 : -1;
    if (LegacyGta3xlwifiProcessGroups()) {
        return KillLegacyProcessGroup(uid, initialPid, signal, once, until);
    }
''')
print('SM-T510 cgroup v1 lifecycle and task profiles applied.')
