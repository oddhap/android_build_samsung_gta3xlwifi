#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed snapshot48 change on top of snapshot46.

source: physical test 2026-11-22 (F-Droid 2.x, session installer): every install
        failed with "RuntimeException: Could not copy bitmap to parcel blob" from
        PackageInstaller.Session.requestUserPreapproval (the app icon bitmap).
        Android 17 HWUI parcels bitmaps larger than 12 KiB through a memfd and, for
        immutable bitmaps, seals it with F_SEAL_FUTURE_WRITE. That seal exists only
        since Linux 5.1; the retained 4.4 kernel returns EINVAL (mm/shmem.c
        F_ALL_SEALS), so every immutable bitmap above 12 KiB fails to parcel.
        F_SEAL_WRITE is not a substitute: before Linux 6.7 it refuses the receiver's
        PROT_READ MAP_SHARED mapping of an O_RDWR memfd (VM_SHARED/i_mmap_writable).
        Fix: only when the immutable seal fails with EINVAL, fall back to the
        Android 15 path (libcutils ashmem region, copy, protection mask reduced to
        PROT_READ before the fd is shared). Kernels with the seal are unaffected;
        mutable bitmaps and all other errors keep the upstream behaviour. libcutils
        already uses /dev/ashmem on this kernel (memfd needs F_SEAL_FUTURE_WRITE), and
        every domain may open ashmem_libcutils_device (snapshot18); no policy change.
"""
import hashlib
import json
from pathlib import Path
import subprocess

root = Path('/srv/android')
src = root/'src/lineage-24.0-arm64'
art = root/'artifacts/lineage-24.0-arm64'
port = root/'ports/lineage-24.0-arm64/lineage-24.0'
base = port/'snapshots'
bitmap = src/'frameworks/base/libs/hwui/jni/Bitmap.cpp'

INCLUDE_OLD = '#include <fcntl.h>\n'
INCLUDE_NEW = '#include <cutils/ashmem.h>\n#include <errno.h>\n#include <fcntl.h>\n'
MEMORY_OLD = '#include <memory>\n'
MEMORY_NEW = '#include <memory>\n#include <mutex>\n'

HELPER_ANCHOR = 'static binder_status_t writeBlob(AParcel* parcel, uint64_t bitmapId, const SkBitmap& bitmap,\n'
HELPER = '''// gta3xlwifi (Linux 4.4): F_SEAL_FUTURE_WRITE needs Linux 5.1, and F_SEAL_WRITE would
// refuse the receiver's PROT_READ MAP_SHARED mapping before Linux 6.7. Use the
// Android 15 path for immutable blobs instead: a libcutils ashmem region whose
// protection mask is reduced to PROT_READ before the fd is shared.
static int writeImmutableAshmemBlob(const char* name, const void* data, size_t size) {
    static std::once_flag logged;
    std::call_once(logged, [] {
        ALOGW("memfd F_SEAL_FUTURE_WRITE unsupported by this kernel; "
              "parceling immutable bitmaps through read-only ashmem");
    });
    base::unique_fd fd(ashmem_create_region(name, size));
    if (fd.get() < 0) {
        return -1;
    }
    void* dest = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
    if (dest == MAP_FAILED) {
        return -1;
    }
    memcpy(dest, data, size);
    munmap(dest, size);
    if (ashmem_set_prot_region(fd.get(), PROT_READ) < 0) {
        return -1;
    }
    return fd.release();
}

'''

SEAL_OLD = '''                    | (immutable ? F_SEAL_FUTURE_WRITE : 0))) {
            return STATUS_UNKNOWN_ERROR;
        }
'''
SEAL_NEW = '''                    | (immutable ? F_SEAL_FUTURE_WRITE : 0))) {
            if (!immutable || errno != EINVAL) {
                return STATUS_UNKNOWN_ERROR;
            }
            fd.reset(writeImmutableAshmemBlob(ashmemId.c_str(), data, size));
            if (fd.get() < 0) {
                return STATUS_NO_MEMORY;
            }
        }
'''


def read(path):
    return json.loads(path.read_text())


work = art/'runtime48-source-selection-20261122-01'
work.mkdir()
before = base/'port-20261122-46'
after = base/'port-20261122-48'
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert read(work/'source-before.json')['passed']
assert not after.exists()
original = bitmap.read_text()
for old in (INCLUDE_OLD, MEMORY_OLD, HELPER_ANCHOR, SEAL_OLD):
    assert original.count(old) == 1, old
assert 'writeImmutableAshmemBlob' not in original and 'cutils/ashmem.h' not in original
updated = (original.replace(INCLUDE_OLD, INCLUDE_NEW).replace(MEMORY_OLD, MEMORY_NEW)
           .replace(HELPER_ANCHOR, HELPER + HELPER_ANCHOR).replace(SEAL_OLD, SEAL_NEW))
edits = {bitmap: (original, updated)}
originals = work/'originals'
originals.mkdir()
for f, (o, _) in edits.items():
    (originals/f.name).write_text(o)
(work/'edits.json').write_text(json.dumps({str(k): {'before_sha256': hashlib.sha256(v[0].encode()).hexdigest(),
    'after_sha256': hashlib.sha256(v[1].encode()).hexdigest()} for k, v in edits.items()}, indent=2)+'\n')
projects = [r['project'] for r in read(before/'source-lock.json')]
try:
    for f, (_, new) in edits.items():
        f.write_text(new)
    subprocess.run(['git', '-C', src/'frameworks/base', 'diff', '--', 'libs/hwui/jni/Bitmap.cpp'],
                   check=True, stdout=(work/'bitmap.diff').open('w'))
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for f, (o, _) in edits.items():
        f.write_text(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
print('PASS staged snapshot48:', after)
