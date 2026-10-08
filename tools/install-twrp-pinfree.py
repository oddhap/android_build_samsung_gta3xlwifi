#!/usr/bin/env python3
"""Install only the checked recovery image with a full-partition rollback copy."""
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parent.parent
adb = '/opt/homebrew/bin/adb'
blocks = '/dev/block/platform/13500000.dwmmc0/by-name/'
size = 47185920
private = root / '.private/twrp-pinfree'
release = root / 'artifacts/twrp-pinfree'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def shell(command):
    return subprocess.check_output([adb, 'shell', command], text=True).strip()

def read_recovery():
    result = subprocess.check_output([adb, 'exec-out',
        f'dd if={blocks}recovery bs=1048576 2>/dev/null'])
    assert len(result) == size
    return result

def partition_hashes():
    names = ('boot', 'vendor', 'dtbo', 'vbmeta')
    output = shell('sha256sum ' + ' '.join(blocks + name for name in names))
    lines = output.splitlines()
    assert len(lines) == len(names)
    return {name: line.split()[0] for name, line in zip(names, lines)}

check = json.loads((release / 'image-check.json').read_text())
crypto = json.loads((release / 'crypto-regression-check.json').read_text())
assert check['build_exit_code'] == 0 and crypto['passed']
candidate = (release / 'recovery-twrp-sm-t510.img').read_bytes()
assert len(candidate) == check['file_bytes'] <= size
assert digest(candidate) == check['sha256']
assert candidate[:8] == b'ANDROID!' and candidate.endswith(b'SEANDROIDENFORCE')
assert candidate[44:48] == bytes.fromhex('a901001c')
assert shell('id -u') == '0'
assert shell('getprop ro.product.device') == 'gta3xlwifi'
assert shell('getprop ro.build.version.incremental') == 'gta3xlwifi.arm64.20261007.170546'
assert shell('getprop ro.twrp.version') == ''
assert shell('getprop sys.boot_completed') == '1'
assert shell('blockdev --getsize64 ' + blocks + 'recovery') == str(size)
assert shell('readlink -f ' + blocks + 'recovery') == '/dev/block/mmcblk0p16'
backup_check = json.loads((private / 'recovery-backup-check.json').read_text())
backup = (private / 'recovery-before.img').read_bytes()
assert len(backup) == size and digest(backup) == backup_check['sha256']
assert read_recovery() == backup, 'Recovery changed after verified backup'
before = partition_hashes()
assert before['vendor'] == '4c320e8bfd9db294e4027acae204a8276c8f06d0e522654f668e38550eded7b9'

staged = '/data/local/tmp/sm-t510-pinfree-candidate.img'
rollback = '/data/local/tmp/sm-t510-pinfree-rollback.img'
for source, target, expected in (
        (private / 'recovery-before.img', rollback, digest(backup)),
        (release / 'recovery-twrp-sm-t510.img', staged, digest(candidate))):
    assert not shell('test -e ' + target + ' && echo exists || true'), target
    subprocess.run([adb, 'push', str(source), target], check=True, capture_output=True)
    assert shell('sha256sum ' + target).split()[0] == expected

written = False
try:
    written = True
    shell(f'dd if={staged} of={blocks}recovery bs=1048576 conv=fsync')
    expected = candidate + backup[len(candidate):]
    actual = read_recovery()
    assert actual == expected, 'Full recovery readback differs'
    assert partition_hashes() == before, 'Another firmware partition changed'
    report = {'passed': True, 'checked_at_utc': datetime.now(timezone.utc).isoformat(),
              'image_sha256': digest(candidate), 'partition_bytes': size,
              'full_partition_sha256': digest(actual), 'full_readback_matches': True,
              'unused_tail_preserved': True, 'other_firmware_partition_hashes_preserved': before,
              'backup_verified': True, 'boot_tested': False}
    (release / 'install-check.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
except BaseException:
    if written:
        shell(f'dd if={rollback} of={blocks}recovery bs=1048576 conv=fsync')
        assert read_recovery() == backup, 'Recovery rollback readback failed'
        print('Previous recovery restored and verified')
    raise
finally:
    shell('rm -f ' + staged + ' ' + rollback)
