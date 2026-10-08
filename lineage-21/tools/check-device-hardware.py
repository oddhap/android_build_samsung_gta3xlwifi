#!/usr/bin/env python3
"""Exercise hardware from a 64-bit app, keeping raw diagnostics private."""
import hashlib
import json
import os
import re
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

os.umask(0o077)
root = Path(__file__).resolve().parent.parent
adb = '/opt/homebrew/bin/adb'
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
private = root/'.private'/f'arm64-hardware-{stamp}'
private.mkdir(mode=0o700)
release = json.loads((root/'artifacts/release/release-signature-check.json').read_text())

def run(*args, binary=False, timeout=30):
    result = subprocess.run([adb,*args],capture_output=True,check=True,timeout=timeout)
    return result.stdout if binary else result.stdout.decode().strip()

assert release['passed']
assert run('shell','getprop','ro.build.version.incremental') == release['build_incremental']
assert run('shell','getprop','sys.boot_completed') == '1'
assert run('shell','getprop','ro.product.cpu.abilist64') == 'arm64-v8a'
assert run('shell','getenforce') == 'Enforcing'
assert run('shell','id','-u') == '0'
assert 'showing=false' in run('shell','dumpsys','window','policy'), 'Unlock the screen'
report = {'tested_at_utc':stamp,'rom_zip_sha256':release['rom_zip_sha256'],
          'build_incremental':release['build_incremental'],
          'camera_images_saved':False,'audio_recorded':False,
          'bluetooth_pairing_tested':False,'long_term_stability_tested':False}
captures = {'hals':('shell','lshal','-i','-S','--neat','--types=b'),
            'wifi':('shell','cmd','wifi','status'),
            'camera':('shell','dumpsys','media.camera'),
            'audio':('shell','dumpsys','media.audio_flinger'),
            'sensors':('shell','dumpsys','sensorservice'),
            'bluetooth':('shell','dumpsys','bluetooth_manager'),
            'power':('shell','dumpsys','power'),
            'network':('shell','dumpsys','connectivity')}
texts = {}
for name, args in captures.items():
    texts[name] = run(*args)
    (private/(name+'.txt')).write_text(texts[name])
def alive(text):
    return {line.split()[0] for line in text.splitlines()
            if len(line.split()) == 2 and line.split()[1] == 'alive'}
baseline = alive((root/'.private/baseline-hardware/hals.txt').read_text())
missing = baseline - alive(texts['hals'])
assert not missing, ('Previously responsive HALs missing',sorted(missing))
report['baseline_responsive_hals_preserved'] = len(baseline)
assert 'Wifi is enabled' in texts['wifi'] and 'COMPLETED' in texts['wifi'], 'Wi-Fi is not connected'
ping = run('shell','ping','-c','3','-W','3','1.1.1.1',timeout=15)
(private/'ping.txt').write_text(ping)
assert re.search(r'\b0% packet loss',ping), 'Wi-Fi internet reachability failed'
report['wifi_connected_and_internet_ping_passed'] = True
apk = root/'artifacts/hardware-tests/gta3xlwifi_hardware_probe.apk'
build = json.loads((root/'artifacts/hardware-probe-build-check.json').read_text())
assert build['passed'] and hashlib.sha256(apk.read_bytes()).hexdigest() == build['apk_sha256']
package = 'org.lineageos.gta3xlwifi.hardwareprobe'
assert 'Success' in run('install','-r','-t',str(apk))
run('shell','pm','grant',package,'android.permission.CAMERA')
run('shell','am','force-stop',package)
launch = run('shell','am','start','-W','-n',package+'/.MainActivity')
assert 'Status: ok' in launch, launch
pid = run('shell','pidof',package)
assert pid.isdigit()
header = run('exec-out',f'dd if=/proc/{pid}/exe bs=64 count=1 2>/dev/null',binary=True)
assert header[:5] == b'\x7fELF\x02' and struct.unpack_from('<H',header,18)[0] == 183
deadline = time.monotonic()+75
while time.monotonic()<deadline:
    log = run('logcat','-d','--pid='+pid,'-v','brief','Gta3xlwifiHardwareProbe:I','*:S')
    (private/'hardware-probe.log').write_text(log)
    if 'FAIL ' in log:
        raise RuntimeError('Hardware probe failed; see '+str(private))
    if 'PASS ALL' in log:
        for expected in ('PASS ACCELEROMETER samples=3','PASS HTTPS status=200','PASS AUDIO frames=44100',
                         'PASS CAMERA facing=front frames=6','PASS CAMERA facing=back frames=6'):
            assert expected in log, expected
        report.update(probe_process_bits=64,accelerometer_samples=3,
                      app_dns_tls_https_passed=True,
                      audio_output_frames=44100,camera_front_frames=6,camera_back_frames=6,
                      hardware_probe_apk_sha256=build['apk_sha256'])
        break
    time.sleep(1)
else:
    raise RuntimeError('Hardware probe timed out; see '+str(private))
run('shell','input','keyevent','KEYCODE_HOME')
report['passed'] = True
(root/'artifacts'/f'arm64-device-hardware-{stamp}.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
