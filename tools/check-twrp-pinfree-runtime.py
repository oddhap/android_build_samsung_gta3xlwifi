#!/usr/bin/env python3
"""Verify real automatic CE access and a stable recovery process for one minute."""
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parent.parent
adb = '/opt/homebrew/bin/adb'
private = root / '.private/twrp-pinfree'
release = root / 'artifacts/twrp-pinfree'
probe = '/data/media/0/Download/.twrp-pinfree-probe'
expected = b'sm-t510-pinfree-recovery-test-20261007\nrecovery-write-confirmed\n'

def shell(command):
    return subprocess.check_output([adb, 'shell', command], text=True).strip()

def binary(command):
    return subprocess.check_output([adb, 'exec-out', command])

assert shell('getprop ro.twrp.version') == '3.7.1_12'
assert shell('getprop ro.product.device') == 'gta3xlwifi'
assert shell('id -u') == '0'
assert shell('getprop twrp.decrypt.done') == 'true'
pid = shell('pidof recovery')
assert pid.isdigit()
assert binary('cat ' + probe) == expected
assert binary('dd if=/data/system_ce/0/accounts_ce.db bs=16 count=1 2>/dev/null') == b'SQLite format 3\0'
check = json.loads((release / 'image-check.json').read_text())
for path, field in (('/system/bin/recovery', 'recovery_elf_sha256'),
                    ('/system/lib/libfscrypttwrp.so', 'fscrypt_library_sha256')):
    assert shell('sha256sum ' + path).split()[0] == check[field]
assert shell('getenforce') == 'Enforcing'

start = time.monotonic()
samples = 0
while True:
    assert shell('pidof recovery') == pid, 'Recovery process restarted'
    assert shell('getprop twrp.decrypt.done') == 'true'
    assert binary('cat ' + probe) == expected
    samples += 1
    if time.monotonic() - start >= 60:
        break
    time.sleep(5)

log = binary('cat /tmp/recovery.log').decode(errors='replace')
(private / 'candidate-final-recovery.log').write_text(log)
crash = subprocess.check_output([adb, 'logcat', '-b', 'all', '-d'], text=True)
(private / 'candidate-final-logcat.txt').write_text(crash)
assert log.count('Starting TWRP ') == 1
assert 'Successfully decrypted with default password.' in log
assert 'Synthetic password authentication failed' not in log
assert not re.search(r'Fatal signal|SIGSEGV', crash)
keys = binary('find /data/misc/vold/user_keys /data/unencrypted -type f -exec sha256sum {} \\;').decode()
(private / 'keys-final-in-recovery.txt').write_text(keys)
before = (private / 'keys-final-before.txt').read_text()
assert sorted(keys.splitlines()) == sorted(before.splitlines()) and len(keys.splitlines()) == 13
install = json.loads((release / 'install-check.json').read_text())
assert shell('sha256sum /dev/block/platform/13500000.dwmmc0/by-name/recovery').split()[0] == install['full_partition_sha256']
shell('printf "final-pinfree-recovery-write\\n" >> ' + probe + '; sync')
assert binary('cat ' + probe) == expected + b'final-pinfree-recovery-write\n'
report = {'passed': True, 'checked_at_utc': datetime.now(timezone.utc).isoformat(),
          'image_sha256': check['sha256'], 'credential': 'none',
          'automatic_ce_decryption': True, 'stable_recovery_pid': int(pid),
          'measured_stability_seconds': round(time.monotonic() - start, 1),
          'stability_samples': samples, 'single_recovery_start': True,
          'no_fatal_signals': True, 'media_probe_read_and_write': True,
          'ce_sqlite_header_readable': True, 'encryption_key_files_unchanged': 13,
          'recovery_elf_matches_packed_image': True,
          'fscrypt_library_matches_packed_image': True,
          'full_recovery_partition_unchanged_since_install': True,
          'global_selinux': 'Enforcing', 'android_return_tested': False}
(release / 'pinfree-final-recovery-check.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
