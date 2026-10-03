#!/usr/bin/env python3
"""Enable existing HIDL 4 audio client paths and skip unavailable GPU BPF metrics."""
from pathlib import Path

top = Path('/srv/android/src/lineage-21.0')

def edit(name, before, after):
    path = top / name
    source = path.read_text()
    if after in source:
        return
    if source.count(before) != 1:
        raise SystemExit(f'Unexpected source anchor: {name}')
    path.write_text(source.replace(before, after, 1))

name = 'frameworks/av/media/libaudiohal/impl/Android.bp'
path = top / name
source = path.read_text()
if 'name: "libaudiohal@4.0"' not in source:
    start = source.index('cc_library_shared {\n    name: "libaudiohal@5.0"')
    end = source.index('\ncc_library_shared {', start + 1)
    module = source[start:end].replace('@5.0', '@4.0').replace('-DMAJOR_VERSION=5', '-DMAJOR_VERSION=4')
    path.write_text(source[:start] + module + '\n' + source[start:])

edit('frameworks/av/media/libaudiohal/FactoryHal.cpp',
     'static const std::array<AudioHalVersionInfo, 5> sAudioHALVersions',
     'static const std::array<AudioHalVersionInfo, 6> sAudioHALVersions')
edit('frameworks/av/media/libaudiohal/FactoryHal.cpp',
     '    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 5, 0),\n};',
     '    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 5, 0),\n'
     '    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 4, 0),\n};')
edit('frameworks/base/media/java/android/media/AudioHalVersionInfo.java',
     'List.of(AIDL_1_0, HIDL_7_1, HIDL_7_0, HIDL_6_0, HIDL_5_0);',
     'List.of(AIDL_1_0, HIDL_7_1, HIDL_7_0, HIDL_6_0, HIDL_5_0, HIDL_4_0);')

edit('frameworks/native/services/gpuservice/gpuwork/GpuWork.cpp',
     '#include <android-base/stringprintf.h>',
     '#include <android-base/properties.h>\n#include <android-base/stringprintf.h>')
edit('frameworks/native/services/gpuservice/gpuwork/GpuWork.cpp',
     'void GpuWork::initialize() {\n',
     'void GpuWork::initialize() {\n'
     '    if (!base::GetBoolProperty("ro.kernel.ebpf.supported", true)) {\n'
     '        ALOGI("GPU BPF accounting unavailable on this kernel");\n'
     '        return;\n'
     '    }\n')
print('Legacy audio client and GPU BPF capability handling applied.')
