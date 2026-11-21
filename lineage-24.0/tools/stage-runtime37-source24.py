#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot37: remove log errors with a clean cause (build-35 log review).

1. external/iptables: Linux 4.4 registers CONNMARK only as revision 1, while
   libxt_CONNMARK also offers revision 2. xtables_find_target() registers
   revision 1 but leaves the unsupported revision 2 pending, so every later
   lookup in a long-lived iptables-restore (netd's exact -S readbacks) printed
   "Extension CONNMARK is not supported, missing kernel module?" and netd
   logged the whole listing as an error. Warn only when no revision of the
   extension is registered. Listing output, rule parsing and netd's exact
   readback verification are unchanged.
2. frameworks/base FileIntegrity: setUpFsVerity() is documented as "if
   supported"; the framework predicate for that is
   VerityUtils.isFsVeritySupported() (launch API >= 30). SM-T510 launched with
   API 28 on Linux 4.4 without fs-verity, so every ResilientAtomicFile /
   AccessPersistence write failed (ENOTTY/EACCES). Skip only there.
3. system/core libcutils: is_memfd_fd() readlinks /proc/self/fd/N for every
   fd. WebView renderers' seccomp sandbox denies that (EPERM). memfds are
   regular files and ashmem regions character devices, so a non-regular fd is
   rejected before the readlink. memfd seal checks and legacy ashmem
   validation are unchanged; no ashmem open is re-allowed.
4. system/core init mount_handler: on legacy system-as-root without dm-verity
   neither the "system" nor "vroot" dm device exists; probe quietly with
   GetState() before the logging lookup on every mount event.
Policy, vendor, kernel unchanged from build 36.
"""
import hashlib, json, subprocess
from pathlib import Path

src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261120-36', port/'snapshots/port-20261120-37'
work = art/'runtime37-lognoise-selection-20261120-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
edits = {}

# 1. iptables: first occurrence is xtables_find_match(), second xtables_find_target().
f = src/'external/iptables/libxtables/xtables.c'
o = f.read_text()
anchor = ('\tif (seen && !found)\n'
          '\t\tfprintf(stderr,\n'
          '\t\t\t"Warning: Extension %s is not supported, missing kernel module?\\n",\n'
          '\t\t\tname);\n')
assert o.count(anchor) == 2 and 'gta3xlwifi' not in o
head, mid, tail = o.split(anchor)
assert 'xtables_find_match(const char *name' in head and 'xtables_find_target(const char *name' in mid


def warn(registered):
    return ('\t/* A newer revision the kernel lacks (e.g. CONNMARK revision 2 on\n'
            '\t * Linux 4.4) stays pending after an older revision was registered;\n'
            '\t * warn only when no revision of the extension is usable. */\n'
            '\tif (seen && !found) {\n'
            f'\t\tfor (ptr = {registered}; ptr; ptr = ptr->next)\n'
            '\t\t\tif (extension_cmp(name, ptr->name, ptr->family))\n'
            '\t\t\t\tbreak;\n'
            '\t\tif (ptr == NULL)\n'
            '\t\t\tfprintf(stderr,\n'
            '\t\t\t\t"Warning: Extension %s is not supported, missing kernel module?\\n",\n'
            '\t\t\t\tname);\n'
            '\t}\n')


u = head + warn('xtables_matches') + mid + warn('xtables_targets') + tail
edits[f] = (o, u)

# 2. FileIntegrity: honour the framework fs-verity support predicate.
f = src/'frameworks/base/services/core/java/com/android/server/security/FileIntegrity.java'
o = f.read_text()
anchor = ('            throws IOException {\n'
          '        VerityUtils.setUpFsverity(parcelFileDescriptor.getFd());\n'
          '    }\n')
assert o.count(anchor) == 1 and 'isFsVeritySupported' not in o
assert o.count('import com.android.internal.security.VerityUtils;\n') == 1
u = o.replace(anchor, '            throws IOException {\n'
              '        // Devices launched before Android 11 need not support fs-verity (SM-T510:\n'
              '        // Linux 4.4, the ioctl fails with ENOTTY). Skip it there instead of\n'
              '        // failing every protected write.\n'
              '        if (!VerityUtils.isFsVeritySupported()) {\n'
              '            return;\n'
              '        }\n'
              '        VerityUtils.setUpFsverity(parcelFileDescriptor.getFd());\n'
              '    }\n')
edits[f] = (o, u)

# 3. libcutils: reject non-regular fds before the /proc/self/fd readlink.
f = src/'system/core/libcutils/ashmem-dev.cpp'
o = f.read_text()
anchor = ('static bool is_memfd_fd(int fd) {\n'
          '    std::string fd_path = android::base::StringPrintf("/proc/self/fd/%d", fd);\n')
assert o.count(anchor) == 1 and o.count('if (fstat(fd, &st) == -1) return -1;\n') == 1
u = o.replace(anchor, 'static bool is_memfd_fd(int fd) {\n'
              '    // A memfd is a regular shmem file; an ashmem region is a character device.\n'
              '    // Reject non-regular fds first so they never need the readlink below,\n'
              '    // which sandboxed processes (WebView renderer seccomp) are denied.\n'
              '    struct stat st;\n'
              '    if (fstat(fd, &st) == 0 && !S_ISREG(st.st_mode)) {\n'
              '        return false;\n'
              '    }\n\n'
              '    std::string fd_path = android::base::StringPrintf("/proc/self/fd/%d", fd);\n')
edits[f] = (o, u)

# 4. init mount_handler: quiet probe before the logging dm lookup.
f = src/'system/core/init/mount_handler.cpp'
o = f.read_text()
anchor = ('        if (dm.GetDmDevicePathByName("system", &path) || dm.GetDmDevicePathByName("vroot", &path)) {\n')
assert o.count(anchor) == 1 and o.count('#include <libdm/dm.h>\n') == 1
u = o.replace(anchor, '        // Legacy system-as-root without dm-verity has neither device: probe\n'
              '        // quietly so each mount event does not log DM_DEV_STATUS failures.\n'
              '        if ((dm.GetState("system") != dm::DmDeviceState::INVALID &&\n'
              '             dm.GetDmDevicePathByName("system", &path)) ||\n'
              '            (dm.GetState("vroot") != dm::DmDeviceState::INVALID &&\n'
              '             dm.GetDmDevicePathByName("vroot", &path))) {\n')
edits[f] = (o, u)

originals = work/'originals'
originals.mkdir()
for f, (o, _) in edits.items():
    (originals/(f.name + '.original')).write_text(o)
(work/'edits.json').write_text(json.dumps({str(k): {'before_sha256': hashlib.sha256(v[0].encode()).hexdigest(),
    'after_sha256': hashlib.sha256(v[1].encode()).hexdigest()} for k, v in edits.items()}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    for f, (_, u) in edits.items():
        f.write_text(u)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for f, (o, _) in edits.items():
        f.write_text(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime36-inputs-20261120-01/report.json'
r = json.loads(p.read_text())
assert r['passed']
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p), runtime_prebuilts_changed=False)
out = art/'runtime37-inputs-20261120-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot37 log-noise corrections:', after)
