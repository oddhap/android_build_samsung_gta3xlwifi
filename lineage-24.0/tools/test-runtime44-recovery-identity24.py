#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-test the actual snapshot44 recovery preflight source against real TWRP images.

Compiles recovery_header_sync.cpp in its own RECOVERY_HEADER_SYNC_HOST_TEST mode
(regular-file input instead of the block device) and runs --preflight on the
installed owner-approved TWRP (fstab without /product, ABGR colour, 33875693...),
its predecessor 96b3de24... (the pre-write backup) and 3821cd28.... All must be
recognized with the target word 0x220001ab; a raised word, a single flipped
ramdisk byte of the new image and an unknown image must be refused. The device
binary is the packaged ARM32 build of the same source (checked separately).
"""
import hashlib, json, shutil, subprocess, sys
from pathlib import Path
T = Path('/srv/android/src/lineage-24.0-arm64')
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
O = A/sys.argv[1]
O.mkdir()
NEW = A/'runtime44-recovery-images-20261121-01/recovery-fstab-abgr-partition.img'
PREV = A/'runtime39-recovery-images-20261121-01/recovery-a-partition.img'
OLD = A/'runtime39-recovery-images-20261121-01/pre-a-recovery-partition.img'
def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1048576), b''): h.update(b)
    return h.hexdigest()
assert sha(NEW) == '33875693066aeb5e9f27bc2d469c3052b438552395cb476ed0d8340348765f05'
assert sha(PREV) == '96b3de24d7c36b8abe390db35e8a098e1c4d69500105f0a127ea09beaccb5e61'
assert sha(OLD) == '3821cd28172b3b4af07f8a86f5f88de039bb893c43dfb7eb8cb785596e41d7d5'
data = bytearray(NEW.read_bytes()[:40271888]); data[44:48] = b'\0\0\0\0'
assert hashlib.sha256(data).hexdigest() == 'de91185c3dbbed822612c5478780aa0bd4cb1c77c0b20c42e29cd0301b3b65bb'
source = T/'device/samsung/gta3xlwifi/recovery-header-sync/recovery_header_sync.cpp'
sel = json.loads((A/'runtime44-source-selection-20261121-01/edits.json').read_text())
assert sha(source) == sel[str(source)]['after_sha256']
exe = O/'recovery-header-sync-host'
subprocess.run(['g++', '-std=c++17', '-O1', '-Wall', '-Wextra', '-Werror', '-fexceptions', '-Wno-deprecated-declarations',
                '-DRECOVERY_HEADER_SYNC_HOST_TEST', str(source), '-o', str(exe), '-lcrypto'], check=True)
tampered = O/'tampered.img'
shutil.copyfile(NEW, tampered)
with tampered.open('r+b') as f:
    f.seek(30000000); b = f.read(1); f.seek(30000000); f.write(bytes([b[0] ^ 1]))
unknown = O/'unknown.img'
with unknown.open('wb') as f:
    f.write(NEW.read_bytes()[:2048]); f.truncate(47185920)
cases = []
def run(label, image, word, ok):
    st = O/(label + '.status')
    r = subprocess.run([str(exe), '--preflight', word, '--test-image', str(image), '--status-file', str(st)],
                       capture_output=True, text=True)
    assert (r.returncode == 0) == ok, (label, r.returncode, r.stdout, r.stderr)
    cases.append({'case': label, 'rc': r.returncode, 'stdout': r.stdout.strip(), 'stderr': r.stderr.strip()})
run('fstab-abgr-twrp-accepted', NEW, '0x220001ab', True)
run('previous-96b3de24-accepted', PREV, '0x220001ab', True)
run('older-3821cd28-accepted', OLD, '0x220001ab', True)
run('raised-word-refused', NEW, '0x220001ac', False)
run('tampered-ramdisk-refused', tampered, '0x220001ab', False)
run('unknown-image-refused', unknown, '0x220001ab', False)
tampered.unlink(); unknown.unlink()
(O/'report.json').write_text(json.dumps({'passed': True, 'scope': __doc__, 'source_sha256': sha(source),
    'new_recovery_sha256': sha(NEW), 'previous_recovery_sha256': sha(PREV), 'older_recovery_sha256': sha(OLD),
    'host_binary_sha256': sha(exe), 'cases': cases, 'device_touched': False}, indent=2)+'\n')
print('PASS host preflight recognizes TWRP 33875693 and its predecessors; refusals intact')
