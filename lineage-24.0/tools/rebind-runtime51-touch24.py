#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebind the touch/double-tap host proof to the snapshot51 power-boost retry change.

Snapshot51 rewrites the boost error handling in device power/Power.cpp and adds a
host test to power/Android.bp (plus RetryBackoff.h/RetryBackoffTest.cpp). The touch
path is unchanged: writeTouchControl, the DOUBLE_TAP_TO_WAKE/INTERACTIVE branches,
the TouchWake member and the mode() return are required verbatim. Every other file
bound by the runtime43 proof (JNI, TouchWake.h/test, BoostWindow, BoardConfig) and
the kernel must still be byte-identical; the two changed files must be exactly the
staged runtime51 texts with the runtime43 hashes as their before-hashes; the
touch-wake host test must have passed in the runtime51 build. Physical double-tap
evidence is carried over, not re-tested. Nothing in the source tree is written.
"""
import hashlib
import json
from pathlib import Path

root = Path('/srv/android')
top = root/'src/lineage-24.0-arm64'
art = root/'artifacts/lineage-24.0-arm64'
previous = art/'runtime43-touch-kernel-rebind-20261121-01/touch-host-proof.json'
edits = art/'runtime51-source-selection-20261123-01/edits.json'
tests = art/'runtime51-product-build-20261123-01/host-tests.json'
output = art/'runtime51-touch-rebind-20261123-01'
CHANGED = ['device/samsung/gta3xlwifi/power/Power.cpp', 'device/samsung/gta3xlwifi/power/Android.bp']
ADDED = ['device/samsung/gta3xlwifi/power/RetryBackoff.h', 'device/samsung/gta3xlwifi/power/RetryBackoffTest.cpp']
TOUCH_TEXT = [
    '''    static bool writeTouchControl(TouchControl control, bool enabled) {
        const char* path = control == TouchControl::DoubleTap
                ? "/sys/class/sec/tsp/double_tap_to_wake"
                : "/sys/class/sec/tsp/input_enabled";
        const char value = enabled ? '1' : '0';
        unique_fd fd(open(path, O_WRONLY | O_CLOEXEC));
        if (!fd.ok() || TEMP_FAILURE_RETRY(write(fd.get(), &value, 1)) != 1) {
            ALOGE("Touch power control failed: %s=%c errno=%d", path, value, errno);
            return false;
        }
        std::string readback;
        if (!android::base::ReadFileToString(path, &readback) ||
                android::base::Trim(readback) != std::string(1, value)) {
            ALOGE("Touch power readback failed: %s=%c", path, value);
            return false;
        }
        return true;
    }
''',
    '''        if (static_cast<Mode>(value) == Mode::DOUBLE_TAP_TO_WAKE)
            return mTouch.doubleTap(enabled);
        const bool touchHandled = static_cast<Mode>(value) == Mode::INTERACTIVE &&
                                  mTouch.interactive(enabled);
''',
    '    TouchWake mTouch{writeTouchControl};\n',
    '        return mReady || touchHandled;\n',
]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as s:
        for block in iter(lambda: s.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


assert not output.exists()
p = json.loads(previous.read_text())
assert p['passed']
e = json.loads(edits.read_text())
t = json.loads(tests.read_text())
assert t['passed'] and t['tests']['gta3xlwifi-touch-wake-test']['returncode'] == 0
for name, digest in p['source_sha256'].items():
    if name in CHANGED:
        meta = e[str(top/name)]
        assert meta['before_sha256'] == digest, name
        assert sha(top/name) == meta['after_sha256'], name
    else:
        assert sha(top/name) == digest, name
assert set(CHANGED) <= set(p['source_sha256'])
for name in ADDED:
    assert e[str(top/name)]['before_sha256'] is None and sha(top/name) == e[str(top/name)]['after_sha256']
assert sha(top/'device/samsung/gta3xlwifi/prebuilt/Image') == p['kernel_sha256']
power = (top/CHANGED[0]).read_text()
for text in TOUCH_TEXT:
    assert power.count(text) == 1, text[:60]
r = dict(p)
r['source_sha256'] = {**{n: sha(top/n) for n in p['source_sha256']}, **{n: sha(top/n) for n in ADDED}}
r['tested_host_binaries'] = sorted(set(p['tested_host_binaries']) | {'RetryBackoffTest'})
r['rebound_from'] = str(previous)
r['rebound_from_sha256'] = sha(previous)
r['rebinding_scope'] = ('Rebind the touch/double-tap proof to snapshot51 (power-boost retry). Power.cpp and '
                        'power/Android.bp changed only in the boost error handling and an added host test; the '
                        'touch path is required verbatim. Physical double-tap evidence is carried over, not re-tested.\n')
r['runtime51_host_tests_sha256'] = sha(tests)
r['runtime51_edits_sha256'] = sha(edits)
r['physical_double_tap_wake_tested'] = False
output.mkdir()
(output/'touch-host-proof.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS runtime51 touch proof rebind:', output/'touch-host-proof.json')
