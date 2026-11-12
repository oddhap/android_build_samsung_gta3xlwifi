#!/usr/bin/env python3
"""Run the real simple-mapping method with Android's actual Spline on a host JVM."""
from pathlib import Path
import subprocess,tempfile,json,re,hashlib,argparse
ap=argparse.ArgumentParser();ap.add_argument('--top',type=Path,required=True);ap.add_argument('--report',type=Path,required=True);a=ap.parse_args()
f=a.top/'frameworks/base/services/core/java/com/android/server/display/DisplayDeviceConfig.java'
s=f.read_text();start=s.index('    private void setSimpleMappingStrategyValues() {');end=s.index('\n    }',start)+6
method=s[start:end]
spline=a.top/'frameworks/base/core/java/android/util/Spline.java'
java=a.top/'prebuilts/jdk/jdk17/linux-x86/bin'
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'android/util').mkdir(parents=True);(p/'android/util/Spline.java').write_bytes(spline.read_bytes())
 source='import android.util.Spline;\npublic class BacklightMinimumTest {\n float[] mNits, mBacklight;\n float mBacklightMinimum, mBacklightMaximum;\n Spline mBrightnessToBacklightSpline, mBacklightToBrightnessSpline;\n'+method+'\n static void eq(float actual,float expected) { if(Math.abs(actual-expected)>0.00001f) throw new AssertionError(actual+" != "+expected); }\n public static void main(String[] args) {\n  for(float min:new float[]{0f,0.011764706f,0.05f}) {\n   BacklightMinimumTest t=new BacklightMinimumTest();\n   t.mBacklightMinimum=min;t.mBacklightMaximum=1f;t.setSimpleMappingStrategyValues();\n   eq(t.mBrightnessToBacklightSpline.interpolate(0f),min);\n   eq(t.mBrightnessToBacklightSpline.interpolate(1f),1f);\n   float previous=min;\n   for(int i=0;i<=1000;i++) {\n    float logical=i/1000f, physical=t.mBrightnessToBacklightSpline.interpolate(logical);\n    if(physical<min || physical>1f || physical<previous) throw new AssertionError("Invalid range");\n    eq(t.mBacklightToBrightnessSpline.interpolate(physical),logical);previous=physical;\n    if(min==0f) eq(physical,logical);\n   }\n  }\n  System.out.println("PASS: minimum, maximum, monotonicity, inverse and default identity");\n }\n}\n'
 (p/'BacklightMinimumTest.java').write_text(source)
 subprocess.run([str(java/'javac'),'-d',d,str(p/'android/util/Spline.java'),str(p/'BacklightMinimumTest.java')],check=True)
 subprocess.run([str(java/'java'),'-cp',d,'BacklightMinimumTest'],check=True)
caller=(a.top/'frameworks/base/services/core/java/com/android/server/display/LocalDisplayAdapter.java').read_text()
assert re.search(r'if \(brightness == PowerManager.BRIGHTNESS_OFF_FLOAT\) \{\s*return PowerManager.BRIGHTNESS_OFF_FLOAT;\s*\} else \{\s*return getDisplayDeviceConfig\(\).getBacklightFromBrightness\(brightness\);',caller)
a.report.write_text(json.dumps({'passed':True,'actual_framework_method_and_spline_compiled':True,'minimums_tested':[0,0.011764706,0.05],'samples_per_minimum':1001,'screen_off_bypass_present':True,'source_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'full_android_runtime_tested':False},indent=2)+'\n')
