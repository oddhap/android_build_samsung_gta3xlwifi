"""Owner request 2026-11-21: write the reviewed TWRP without /product and with ABGR colour order.

NOT RUN until the owner confirms this concrete plan and the hashes below.
Runs against TWRP (root shell). Steps, each stopping on any mismatch:
 1. Recovery partition must be exactly the installed image 96b3de24... (by-name -> mmcblk0p16).
 2. Full partition backup to the host and SHA verification.
 3. Push the new image to /tmp, verify its SHA on the device, dd it to the partition, fsync.
 4. Full readback must equal the new image. On any failure after writing, the backup is
    written back and verified.
Kernel, recovery DTBO, os_version 0x220001ab and all ramdisk files except recovery.fstab,
twrp.fstab, libminuitwrp.so and ramdisk-files.sha256sum are unchanged (see report.json).
No other partition is touched; no data is formatted.
"""
import hashlib, json, subprocess
from pathlib import Path

W = Path(__file__).resolve().parent
adb = ['/opt/homebrew/bin/adb', '-s', 'R52N8038D1L']
DEV = '/dev/block/mmcblk0p16'
SIZE = 47185920
BEFORE = '96b3de24d7c36b8abe390db35e8a098e1c4d69500105f0a127ea09beaccb5e61'
AFTER = '33875693066aeb5e9f27bc2d469c3052b438552395cb476ed0d8340348765f05'
image = W/'recovery-fstab-abgr-partition.img'
backup = W/'pre-fstab-abgr-recovery-partition.img'
report = W/'write-report.json'
sha = lambda b: hashlib.sha256(b).hexdigest()
R = {'owner_request': 'TWRP fstab without /product + ABGR colour, 2026-11-21', 'scope': __doc__, 'before_sha256': BEFORE, 'after_sha256': AFTER}


def call(args, timeout=180, **kw):
    return subprocess.run(adb + args, capture_output=True, timeout=timeout, **kw)


def sh(cmd, timeout=180):
    r = call(['shell', cmd], timeout)
    assert r.returncode == 0, (cmd, r.returncode, r.stdout, r.stderr)
    return r.stdout.decode()


def read():
    r = call(['exec-out', 'dd', 'if=' + DEV, 'bs=65536', 'count=720', 'status=none'])
    assert r.returncode == 0 and len(r.stdout) == SIZE, (r.returncode, len(r.stdout))
    return r.stdout


def write_from_tmp(local, remote):
    assert call(['push', str(local), remote]).returncode == 0
    assert sh('sha256sum ' + remote).split()[0] == sha(local.read_bytes())
    sh('dd if=' + remote + ' of=' + DEV + ' bs=65536 conv=fsync status=none && sync', 300)


new = image.read_bytes()
assert len(new) == SIZE and sha(new) == AFTER
assert json.loads((W/'report.json').read_text())['output_partition_sha256'] == AFTER
assert not backup.exists() and not report.exists()
assert call(['get-state']).stdout.strip() == b'recovery'
assert sh('id -u').strip() == '0'
assert sh('readlink -f /dev/block/platform/13500000.dwmmc0/by-name/recovery').strip() == DEV
written = False
original = None
try:
    original = read()
    assert sha(original) == BEFORE, 'recovery partition is not the installed verified image'
    # 2. backup.
    backup.write_bytes(original)
    assert sha(backup.read_bytes()) == BEFORE
    R.update(backup=backup.name, backup_verified=True, state='before write')
    report.write_text(json.dumps(R, indent=2) + '\n')
    # 3. write.
    written = True
    write_from_tmp(image, '/tmp/recovery-fstab-abgr-partition.img')
    sh('rm -f /tmp/recovery-fstab-abgr-partition.img')
    # 4. readback.
    actual = read()
    assert actual == new, 'Full partition readback differs from the reviewed image'
    R.update(passed=True, readback_partition_sha256=sha(actual), state='reviewed image written and fully verified')
except Exception as e:
    R.update(passed=False, error=repr(e))
    if written and original is not None:
        try:
            write_from_tmp(backup, '/tmp/pre-fstab-abgr-recovery-partition.img')
            R['original_restored'] = read() == original
        except Exception as e2:
            R['restore_error'] = repr(e2)
    raise
finally:
    report.write_text(json.dumps(R, indent=2) + '\n')
    print(json.dumps({k: v for k, v in R.items() if k != 'scope'}, indent=2))
