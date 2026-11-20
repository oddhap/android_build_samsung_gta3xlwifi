#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage the gta3xlwifi HIDL-only Bluetooth audio shim from AOSP sources.

Samsung's 32-bit Android 11 audio HAL (VNDK v30) never registers AOSP's
IBluetoothAudioProvidersFactory. The provider and the bluetooth audio module
share an in-process session, so this shim is one 32-bit audio module that
also registers the HIDL 2.0 provider factory inside the audio HAL process.
AIDL paths are removed by exact, verified edits (VNDK v30 has no AIDL
Bluetooth audio libraries). Upstream files are copied, never modified.
"""
import hashlib, json, re, shutil, sys
from pathlib import Path

T = Path('/srv/android/src/lineage-24.0-arm64')
out = Path(sys.argv[1])
assert not out.exists()
hw = T/'packages/modules/Bluetooth/system/audio_bluetooth_hw'
prov = T/'hardware/interfaces/bluetooth/audio/2.0/default'
sess = T/'hardware/interfaces/bluetooth/audio/utils/session'
cfg = T/'frameworks/av/services/audiopolicy/config/bluetooth_audio_policy_configuration.xml'
d = out/'btaudio'
(d/'vendor/etc/vintf/manifest').mkdir(parents=True)
inputs = {}


def copy(src, name=None):
    inputs[str(src)] = hashlib.sha256(src.read_bytes()).hexdigest()
    dst = d/(name or src.name)
    shutil.copyfile(src, dst)
    return dst


def edit(path, old, new, count=1):
    s = path.read_text()
    assert s.count(old) == count, (path.name, old[:60], s.count(old))
    path.write_text(s.replace(old, new))


for f in ['audio_bluetooth_hw.cc', 'device_port_proxy.h', 'device_port_proxy_hidl.cc',
          'device_port_proxy_hidl.h', 'stream_apis.cc', 'stream_apis.h', 'utils.cc', 'utils.h']:
    copy(hw/f)
for f in prov.iterdir():
    if f.suffix in ('.cpp', '.h'):
        copy(f)
for f in sess.iterdir():
    if f.suffix in ('.cpp', '.h'):
        copy(f)
copy(cfg)

# stream_apis.cc: HIDL ports only.
s = d/'stream_apis.cc'
edit(s, '#include "BluetoothAudioSession.h"\n', '')
edit(s, '''  } else {
    static_cast<::android::bluetooth::audio::aidl::BluetoothAudioPortAidl*>(
            out->bluetooth_output_.get())
            ->UpdateSourceMetadata(source_metadata_v7);
  }
''', '  }\n')
edit(s, '''  static_cast<::android::bluetooth::audio::aidl::BluetoothAudioPortAidl*>(
          in->bluetooth_input_.get())
          ->UpdateSinkMetadata(sink_metadata);
''', '')
for io, port, kind in [('out', 'bluetooth_output_', 'Out'), ('in', 'bluetooth_input_', 'In')]:
    edit(s, f'''  if (::aidl::android::hardware::bluetooth::audio::BluetoothAudioSession::IsAidlAvailable()) {{
    {io}->{port} =
            std::make_unique<::android::bluetooth::audio::aidl::BluetoothAudioPortAidl{kind}>();
    {io}->is_aidl = true;
  }} else {{
    {io}->{port} =
            std::make_unique<::android::bluetooth::audio::hidl::BluetoothAudioPortHidl{kind}>();
    {io}->is_aidl = false;
  }}
''', f'''  // gta3xlwifi: VNDK v30 vendor has no AIDL Bluetooth audio provider.
  {io}->{port} =
          std::make_unique<::android::bluetooth::audio::hidl::BluetoothAudioPortHidl{kind}>();
  {io}->is_aidl = false;
''')
assert 'aidl::BluetoothAudioPortAidl' not in s.read_text()

# Session: drop the HIDL->AIDL middleware forwarding (AIDL never available here).
pat = re.compile(r'\n[ \t]*if \(HidlToAidlMiddleware_2_[01]::IsAidlAvailable\(\)\)\n[ \t]*return [^;]*;')
for name in ['BluetoothAudioSession.cpp', 'BluetoothAudioSession_2_1.cpp']:
    p = d/name
    text = p.read_text()
    text, n = pat.subn('', text)
    assert n >= 1, name
    text = re.sub(r'#include "\.\./aidl_session/HidlToAidlMiddleware_2_[01]\.h"\n', '', text)
    text = re.sub(r'using ::aidl::android::hardware::bluetooth::audio::HidlToAidlMiddleware_2_[01];\n', '', text)
    assert 'HidlToAidl' not in text, name
    p.write_text(text)

# HIDL 2.1 libraries are not in VNDK v30: run the HIDL port on the 2.0 session
# (as Android 11 did). Aliases keep upstream call sites; LE audio and the
# HIDL input datapath (2.1-only) become unsupported.
h, c = d/'device_port_proxy_hidl.h', d/'device_port_proxy_hidl.cc'
edit(h, '#include <android/hardware/bluetooth/audio/2.1/types.h>', '#include <android/hardware/bluetooth/audio/2.0/types.h>')
edit(h, 'using SessionType_2_1 = ::android::hardware::bluetooth::audio::V2_1::SessionType;',
     'using SessionType_2_1 = ::android::hardware::bluetooth::audio::V2_0::SessionType;  // gta3xlwifi: HIDL 2.0')
edit(h, '''    return session_type_hidl_ == SessionType_2_1::LE_AUDIO_SOFTWARE_ENCODING_DATAPATH ||
           session_type_hidl_ == SessionType_2_1::LE_AUDIO_SOFTWARE_DECODED_DATAPATH ||
           session_type_hidl_ == SessionType_2_1::LE_AUDIO_HARDWARE_OFFLOAD_ENCODING_DATAPATH ||
           session_type_hidl_ == SessionType_2_1::LE_AUDIO_HARDWARE_OFFLOAD_DECODING_DATAPATH;''',
     '    return false;  // gta3xlwifi: no LE audio session types in HIDL 2.0')
edit(c, '#include "BluetoothAudioSessionControl_2_1.h"', '#include "BluetoothAudioSessionControl.h"')
edit(c, 'using ::android::bluetooth::audio::BluetoothAudioSessionControl_2_1;',
     'using BluetoothAudioSessionControl_2_1 = ::android::bluetooth::audio::BluetoothAudioSessionControl;')
edit(c, 'using SampleRate_2_1 = ::android::hardware::bluetooth::audio::V2_1::SampleRate;',
     'using SampleRate_2_1 = ::android::hardware::bluetooth::audio::V2_0::SampleRate;')
edit(c, '    case SampleRate_2_1::RATE_8000:\n      return 8000;\n', '')
edit(c, '    case SampleRate_2_1::RATE_32000:\n      return 32000;\n', '')
s = c.read_text()
n1 = s.count('::android::hardware::bluetooth::audio::V2_1::AudioConfiguration')
n2 = s.count('::android::hardware::bluetooth::audio::V2_1::PcmParameters')
assert n1 == 6 and n2 == 3, (n1, n2)
s = s.replace('::android::hardware::bluetooth::audio::V2_1::AudioConfiguration',
              '::android::hardware::bluetooth::audio::V2_0::AudioConfiguration')
s = s.replace('::android::hardware::bluetooth::audio::V2_1::PcmParameters',
              '::android::hardware::bluetooth::audio::V2_0::PcmParameters')
c.write_text(s)
edit(c, '  *interval_us = pcm_cfg.dataIntervalUs;\n  return true;',
     '  (void)pcm_cfg;\n  return false;  // gta3xlwifi: HIDL 2.0 PcmParameters has no data interval')
for dev in ['AUDIO_DEVICE_OUT_BLE_HEADSET', 'AUDIO_DEVICE_OUT_BLE_SPEAKER', 'AUDIO_DEVICE_IN_BLE_HEADSET']:
    s = c.read_text()
    m = re.search(r'    case %s:\n(?:.*\n)*?      break;\n' % dev, s)
    assert m and 'LE_AUDIO' in m.group(0), dev
    c.write_text(s[:m.start()] + s[m.end():])
edit(c, '  return BluetoothAudioSessionControl_2_1::InReadPcmData(session_type_hidl_, buffer, bytes);',
     '  return 0;  // gta3xlwifi: no HIDL 2.0 input datapath')
assert 'V2_1' not in c.read_text() and 'LE_AUDIO' not in c.read_text()
for f in ['BluetoothAudioSession_2_1.cpp', 'BluetoothAudioSupportedCodecsDB_2_1.cpp']:
    (d/f).unlink()

# Register the provider factory inside the audio HAL process on first module open.
edit(d/'audio_bluetooth_hw.cc', '''static int adev_open(const hw_module_t* module, const char* name, hw_device_t** device) {
''', '''extern "C" void gta3xlwifi_register_bt_audio_provider();

static int adev_open(const hw_module_t* module, const char* name, hw_device_t** device) {
  gta3xlwifi_register_bt_audio_provider();
''')
(d/'gta3xlwifi_register.cpp').write_text('''// SPDX-License-Identifier: Apache-2.0
// Registers the AOSP HIDL 2.0 Bluetooth audio provider factory in the audio HAL
// process that loads this module, so provider and stream share one session.
#define LOG_TAG "gta3xlwifi_btaudio"
#include <log/log.h>
#include <mutex>
#include "BluetoothAudioProvidersFactory.h"

using ::android::sp;
using ::android::hardware::bluetooth::audio::V2_0::IBluetoothAudioProvidersFactory;
using ::android::hardware::bluetooth::audio::V2_0::implementation::BluetoothAudioProvidersFactory;

// VNDK v30 libfmq exports only check(bool); current FMQ headers also call this
// overload. Identical to system/libfmq/FmqInternal.cpp.
#include <android-base/logging.h>
namespace android::hardware::details {
void check(bool exp, const char* message) {
  CHECK(exp) << message;
}
}  // namespace android::hardware::details

extern "C" void gta3xlwifi_register_bt_audio_provider() {
  static std::once_flag once;
  static sp<IBluetoothAudioProvidersFactory> factory;
  std::call_once(once, [] {
    factory = new BluetoothAudioProvidersFactory();
    const ::android::status_t status = factory->registerAsService("default");
    ALOGI("IBluetoothAudioProvidersFactory@2.0/default registration: %d", status);
  });
}
''')
srcs = sorted(p.name for p in d.iterdir() if p.suffix in ('.cc', '.cpp'))
(d/'Android.bp').write_text('''// SPDX-License-Identifier: Apache-2.0
// HIDL-only Bluetooth audio module + in-process provider for the VNDK v30
// Samsung audio HAL. Built explicitly; not in PRODUCT_PACKAGES.
cc_library_shared {
    name: "gta3xlwifi_btaudio_shim",
    stem: "audio.bluetooth.exynos7904",
    vendor: true,
    relative_install_path: "hw",
    compile_multilib: "32",
    stl: "c++_static",
    srcs: [
%s    ],
    cflags: ["-Wall", "-Werror", "-Wno-sign-compare", "-Wno-unused-parameter", "-Wno-unused-variable", "-Wno-unused-function"],
    defaults: [
        "latest_android_hardware_audio_common_ndk_static",
        "latest_android_hardware_bluetooth_audio_ndk_static",
    ],
    header_libs: ["libhardware_headers"],
    static_libs: ["libbase"],
    shared_libs: [
        "android.hardware.audio.common@5.0",
        "android.hardware.bluetooth.audio@2.0",
        "libaudioutils",
        "libbinder_ndk",
        "libcutils",
        "libfmq",
        "libhidlbase",
        "liblog",
        "libutils",
    ],
}
''' % ''.join('        "%s",\n' % x for x in srcs))
(d/'vendor/etc/vintf/manifest/gta3xlwifi_btaudio.xml').write_text('''<manifest version="1.0" type="device">
    <hal format="hidl">
        <name>android.hardware.bluetooth.audio</name>
        <transport>hwbinder</transport>
        <version>2.0</version>
        <interface>
            <name>IBluetoothAudioProvidersFactory</name>
            <instance>default</instance>
        </interface>
    </hal>
</manifest>
''')
shutil.move(str(d/'bluetooth_audio_policy_configuration.xml'), str(d/'vendor/etc/bluetooth_audio_policy_configuration.xml'))
(out/'report.json').write_text(json.dumps({'passed': True, 'scope': __doc__, 'upstream_inputs_sha256': inputs,
    'files_sha256': {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(d.rglob('*')) if p.is_file()}}, indent=2)+'\n')
print('PASS staged btaudio shim:', len(srcs), 'sources')
