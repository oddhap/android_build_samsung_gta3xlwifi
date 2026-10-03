#!/usr/bin/env python3
"""Keep GPU memory counters unavailable on kernels without their BPF backend."""
from pathlib import Path

path = Path('/srv/android/src/lineage-21.0/system/memory/libmeminfo/sysmeminfo.cpp')
source = path.read_text()
include = '#include <android-base/properties.h>'
if include not in source:
    source = source.replace('#include <android-base/parseint.h>',
                            '#include <android-base/parseint.h>\n' + include, 1)
anchor = '''#if defined(__ANDROID__) && !defined(__ANDROID_APEX__) && !defined(__ANDROID_VNDK__)
    static constexpr const char kBpfGpuMemTotalMap[]'''
replacement = '''#if defined(__ANDROID__) && !defined(__ANDROID_APEX__) && !defined(__ANDROID_VNDK__)
    // Unavailable GPU counters must not abort system_server during memory reports.
    // The caller preserves its existing unavailable result (Debug returns -1).
    if (!android::base::GetBoolProperty("ro.kernel.ebpf.supported", true)) return false;
    static constexpr const char kBpfGpuMemTotalMap[]'''
if source.count(replacement) == 2:
    print('GPU memory capability guards already applied')
elif source.count(anchor) == 2:
    path.write_text(source.replace(anchor, replacement))
    print('Both GPU memory readers guard the kernel BPF capability')
else:
    raise SystemExit('Unexpected GPU memory reader layout; source left unchanged')
