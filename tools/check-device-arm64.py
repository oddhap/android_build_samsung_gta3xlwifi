#!/usr/bin/env python3
"""Run both actual EGL clients on an identified ARM64 release; Mac-side only.

Requires an unlocked screen. Installs only the standalone test APKs and keeps
raw diagnostics private. This is a graphics/ABI gate, not a full hardware pass.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--release-check', type=Path, required=True)
parser.add_argument('--adb', default='/opt/homebrew/bin/adb')
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
os.umask(0o077)
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
private = root/'.private'/f'arm64-device-{stamp}'
private.mkdir(mode=0o700)
release = json.loads(args.release_check.read_text())
assert release['passed'] and release['updater_static_arm64']
targeted = json.loads((root/'artifacts/targeted-abi-check.json').read_text())
assert targeted['passed']

def adb(*command, binary=False):
    result = subprocess.run([args.adb, *command], capture_output=True, check=True)
    return result.stdout if binary else result.stdout.decode().strip()

def prop(name):
    return adb('shell', 'getprop', name)

assert prop('ro.product.device') == 'gta3xlwifi'
assert prop('sys.boot_completed') == '1'
assert prop('ro.build.version.incremental') == release['build_incremental']
assert prop('ro.system.build.fingerprint') == release['system_build_fingerprint']
assert prop('ro.product.cpu.abilist') == 'arm64-v8a,armeabi-v7a,armeabi'
assert prop('ro.zygote') == 'zygote64_32'
assert adb('shell', 'getenforce') == 'Enforcing'
assert prop('ro.crypto.state') == 'encrypted'
assert adb('shell', 'id', '-u') == '0', 'Run adb root before collecting process ABI evidence'
policy = adb('shell', 'dumpsys', 'window', 'policy')
(private/'window-policy.txt').write_text(policy)
assert re.search(r'\bshowing=false\b', policy), 'Unlock the tablet screen before running graphics tests'

report = {
    'tested_at_utc': stamp,
    'build_incremental': release['build_incremental'],
    'rom_zip_sha256': release['rom_zip_sha256'],
    'boot_completed': True, 'selinux': 'Enforcing',
    'crypto_state': 'encrypted', 'zygote': 'zygote64_32',
    'graphics': {}, 'processes': {},
    'all_hardware_functions_tested': False,
}
for process in ('surfaceflinger', 'zygote64', 'zygote'):
    pid = adb('shell', 'pidof', process).split()
    assert len(pid) == 1, (process, pid)
    header = adb('exec-out', f'dd if=/proc/{pid[0]}/exe bs=64 count=1 2>/dev/null', binary=True)
    bits = 32 if process == 'zygote' else 64
    assert header[:5] == b'\x7fELF' + bytes([1 if bits == 32 else 2]), process
    assert struct.unpack_from('<H', header, 18)[0] == (40 if bits == 32 else 183), process
    report['processes'][process] = {'bits': bits}
    (private/f'{process}-maps.txt').write_text(adb('shell', 'cat', f'/proc/{pid[0]}/maps'))

for bits in (64, 32):
    apk = root/'artifacts/hardware-tests'/f'gta3xlwifi_abi_probe{bits}.apk'
    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    assert digest == targeted['test_apks'][str(bits)]['sha256'], apk
    package = f'org.lineageos.gta3xlwifi.smoke{bits}'
    assert 'Success' in adb('install', '-r', '-t', str(apk))
    adb('shell', 'am', 'force-stop', package)
    # A new process PID prevents a previous baseline PASS from being reused.
    launch = adb('shell', 'am', 'start', '-W', '-n', package+'/org.lineageos.gta3xlwifi.smoke.MainActivity')
    assert 'Status: ok' in launch, launch
    pid = adb('shell', 'pidof', package).strip()
    assert pid.isdigit(), pid
    header = adb('exec-out', f'dd if=/proc/{pid}/exe bs=64 count=1 2>/dev/null', binary=True)
    assert header[:5] == b'\x7fELF' + bytes([1 if bits == 32 else 2])
    assert struct.unpack_from('<H', header, 18)[0] == (40 if bits == 32 else 183)
    deadline = time.monotonic() + 60
    while True:
        log = adb('logcat', '-d', '--pid='+pid, '-v', 'brief', 'Gta3xlwifiAbiProbe:I', '*:S')
        (private/f'graphics{bits}.log').write_text(log)
        if package+' PASS:' in log:
            assert f'ABI={bits}' in log and 'renderer=Mali-G71' in log
            assert '120 shader draws/window buffers/pixel readback' in log
            maps = adb('shell','cat',f'/proc/{pid}/maps')
            (private/f'graphics{bits}-maps.txt').write_text(maps)
            driver = f'/vendor/{"lib64" if bits == 64 else "lib"}/egl/libGLES_mali.so'
            assert driver in maps, 'Mali vendor driver is not mapped in the test process'
            report['graphics'][str(bits)] = {'passed': True, 'frames': 120,
                'pixel_readback': True, 'renderer': 'Mali-G71', 'apk_sha256': digest,
                'process_bits':bits,'vendor_mali_driver_mapped':True}
            break
        if package+' FAIL:' in log or time.monotonic() >= deadline:
            raise RuntimeError(f'ARM{bits} graphics did not pass; private diagnostics: {private}')
        time.sleep(1)

(private/'linkerconfig.txt').write_text(adb('shell', 'cat', '/linkerconfig/ld.config.txt'))
(private/'surfaceflinger.txt').write_text(adb('shell', 'dumpsys', 'SurfaceFlinger'))
report['passed'] = True
destination = root/'artifacts'/f'arm64-device-graphics-{stamp}.json'
destination.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
