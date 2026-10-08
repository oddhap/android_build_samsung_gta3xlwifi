#!/usr/bin/env python3
"""Verify the final native Android boot, CE persistence and test-file cleanup."""
import json
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parent.parent
adb = '/opt/homebrew/bin/adb'
private = root / '.private/twrp-pinfree'
release = root / 'artifacts/twrp-pinfree'
blocks = '/dev/block/platform/13500000.dwmmc0/by-name/'

def shell(command):
    return subprocess.check_output([adb, 'shell', command], text=True, stderr=subprocess.DEVNULL).strip()

def binary(command):
    return subprocess.check_output([adb, 'exec-out', command])

deadline = time.monotonic() + 180
while True:
    try:
        ready = (shell('getprop ro.twrp.version') == '' and
                 shell('getprop sys.boot_completed') == '1' and
                 shell('getprop sys.user.0.ce_available') == 'true')
        if ready:
            break
    except subprocess.CalledProcessError:
        pass
    if time.monotonic() >= deadline:
        raise SystemExit('Android boot or automatic user unlock did not finish')
    time.sleep(3)

subprocess.run([adb, 'root'], check=True)
subprocess.run([adb, 'wait-for-device'], check=True)
assert shell('id -u') == '0'
assert shell('getprop ro.build.version.incremental') == 'gta3xlwifi.arm64.20261007.170546'
assert shell('getprop ro.product.cpu.abilist') == 'arm64-v8a,armeabi-v7a,armeabi'
assert shell('getprop ro.zygote') == 'zygote64_32'
assert shell('getprop ro.crypto.state') == 'encrypted'
assert shell('getprop ro.crypto.type') == 'file'
assert shell('getenforce') == 'Enforcing'
assert 'CredentialType: NONE' in shell('dumpsys lock_settings')
assert 'State: RUNNING_UNLOCKED' in shell('dumpsys user')

native = {}
for name in ('init', 'system_server', 'zygote64', 'vold', 'surfaceflinger'):
    pid = '1' if name == 'init' else shell('pidof ' + name)
    assert pid.isdigit(), name
    header = binary(f'dd if=/proc/{pid}/exe bs=20 count=1 2>/dev/null')
    assert header[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', header, 18)[0] == 183, name
    native[name] = 'ELF64 AArch64'

probe = '/data/media/0/Download/.twrp-pinfree-probe'
assert binary('cat ' + probe) == (b'sm-t510-pinfree-recovery-test-20261007\n'
                                  b'recovery-write-confirmed\nfinal-pinfree-recovery-write\n')
keys = binary('find /data/misc/vold/user_keys /data/unencrypted -type f -exec sha256sum {} \\;').decode()
(private / 'keys-final-after-android.txt').write_text(keys)
before = {s.split(maxsplit=1)[1]: s.split()[0] for s in (private / 'keys-final-before.txt').read_text().splitlines()}
after = {s.split(maxsplit=1)[1]: s.split()[0] for s in keys.splitlines()}
assert before.keys() == after.keys() and len(before) == 13
assert [k for k in before if before[k] != after[k]] == ['/data/unencrypted/per_boot_ref']

install = json.loads((release / 'install-check.json').read_text())
firmware = {name: shell('sha256sum ' + blocks + name).split()[0]
            for name in ('boot', 'vendor', 'dtbo', 'vbmeta')}
assert firmware == install['other_firmware_partition_hashes_preserved']
assert shell('sha256sum ' + blocks + 'recovery').split()[0] == install['full_partition_sha256']
subprocess.run([adb, 'shell', 'rm ' + probe], check=True)
assert shell('test -e ' + probe + ' && echo exists || echo removed') == 'removed'

report = {'passed': True, 'checked_at_utc': datetime.now(timezone.utc).isoformat(),
          'recovery_image_sha256': install['image_sha256'],
          'rom_build': 'gta3xlwifi.arm64.20261007.170546',
          'credential': 'none', 'boot_completed': True, 'automatic_ce_unlock': True,
          'user_state': 'RUNNING_UNLOCKED', 'selinux': 'Enforcing',
          'encryption': 'encrypted/file', 'native_processes': native,
          'recovery_writes_persisted_in_android': True,
          'persistent_crypto_files_unchanged': 12, 'per_boot_reference_regenerated': True,
          'firmware_partition_hashes_preserved': firmware,
          'full_recovery_partition_matches_install': True, 'test_probe_removed': True}
(release / 'final-android-check.json').write_text(json.dumps(report, indent=2) + '\n')
p = release / 'pinfree-final-recovery-check.json'
recovery = json.loads(p.read_text())
recovery['android_return_tested'] = True
p.write_text(json.dumps(recovery, indent=2) + '\n')
print(json.dumps(report, indent=2))
