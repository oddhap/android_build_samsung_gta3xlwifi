#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual display mapping and bitmap fallback code on a host JVM."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

top, report = map(Path, sys.argv[1:])
paths = [Path('frameworks/base')/name for name in (
    'services/core/java/com/android/server/display/DisplayDeviceConfig.java',
    'services/core/java/com/android/server/display/LocalDisplayAdapter.java',
    'core/java/android/inputmethodservice/navigationbar/KeyButtonDrawable.java',
    'core/java/android/util/Spline.java',
)]
display, adapter, drawable, spline = [(top/p).read_text() for p in paths]

def method(source, name):
    return re.search(r'(?m)^    private .*\b' + name + r'\([^\n]*\) \{[\s\S]+?^    }',
                     source).group()

mapping = method(display, 'setSimpleMappingStrategyValues')
fallback = method(drawable, 'preferHardwareBitmap')
assert drawable.count('bitmap = preferHardwareBitmap(bitmap);') == 2
assert re.search(r'if \(brightness == PowerManager.BRIGHTNESS_OFF_FLOAT\) \{\s*'
                 r'return PowerManager.BRIGHTNESS_OFF_FLOAT;\s*\} else \{\s*'
                 r'return getDisplayDeviceConfig\(\).getBacklightFromBrightness\(brightness\);',
                 adapter)
with tempfile.TemporaryDirectory() as tmp:
    directory = Path(tmp)
    (directory/'Spline.java').write_text(spline)
    (directory/'UiBacklightTest.java').write_text('''
import android.util.Spline;
public class UiBacklightTest {
    float[] mNits, mBacklight;
    float mBacklightMinimum, mBacklightMaximum;
    Spline mBrightnessToBacklightSpline, mBacklightToBrightnessSpline;
    static class Bitmap {
        enum Config { HARDWARE }
        Bitmap hardwareResult;
        Bitmap copy(Config config, boolean mutable) {
            if (config != Config.HARDWARE || mutable) throw new AssertionError();
            return hardwareResult;
        }
    }
''' + mapping + '\n' + fallback + '''
    static void check(boolean value) {
        if (!value) throw new AssertionError();
    }
    static void near(float a, float b) { check(Math.abs(a - b) < 0.00001f); }
    public static void main(String[] args) {
        UiBacklightTest t = new UiBacklightTest();
        for (float[] range : new float[][] {{0f, 1f}, {0.011764706f, 1f},
                                            {0.05f, 0.8f}, {0.1f, 0.1f}}) {
            t.mBacklightMinimum = range[0];
            t.mBacklightMaximum = range[1];
            t.setSimpleMappingStrategyValues();
            float previous = range[0];
            for (int i = 0; i <= 1000; i++) {
                float logical = i / 1000f;
                float level = t.mBrightnessToBacklightSpline.interpolate(logical);
                near(level, range[0] + logical * (range[1] - range[0]));
                check(level >= previous && level <= range[1]);
                near(t.mBacklightToBrightnessSpline.interpolate(level),
                        range[0] == range[1] ? 0f : logical);
                previous = level;
            }
        }
        Bitmap software = new Bitmap();
        check(preferHardwareBitmap(software) == software);
        software.hardwareResult = new Bitmap();
        check(preferHardwareBitmap(software) == software.hardwareResult);
    }
}
''')
    jdk = top/'prebuilts/jdk/jdk21/linux-x86/bin'
    subprocess.run([jdk/'javac', '-d', tmp, directory/'Spline.java',
                    directory/'UiBacklightTest.java'], check=True)
    subprocess.run([jdk/'java', '-cp', tmp, 'UiBacklightTest'], check=True)
paths.append(Path('device/samsung/gta3xlwifi/device.mk'))
report.write_text(json.dumps({
    'passed': True,
    'tested_minimum_and_maximum_mapping': True,
    'tested_null_hardware_copy_and_preferred_hardware_copy': True,
    'screen_off_path_preserved': True,
    'ui_runtime_tested': False,
    'source_sha256': {str(p):hashlib.sha256((top/p).read_bytes()).hexdigest() for p in paths},
}, indent=2)+'\n')
print('PASS host backlight and keyboard cache regressions')
