#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host test: the LineageOS 21 OTA header helper accepts the ABGR TWRP now and in future OTAs.

Builds recovery_header_sync.cpp with the host-test switch and runs it only on
regular-file copies padded to the 47185920-byte RECOVERY partition. Checks:
  * new image 947d409b...: preflight supported, nothing written;
  * a chain of future LineageOS 21 OTAs (2026-10 -> 2026-11 -> 2026-12 -> 2027-06):
    apply rewrites only bytes 44..47, and the next preflight still recognizes it;
  * a downgrade and a non-Android-14 word are refused, image unchanged;
  * the previous published TWRP 10c2c2ee... is still recognized and synchronized;
  * a one-byte ramdisk change is "unsupported" and left unchanged (not blocked);
  * the unmodified helper source (published 20261127 build) reports the new image
    as unsupported (keeps it unchanged and installs; no header synchronization).
"""
import argparse, hashlib, struct, subprocess, tempfile
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--old-source', type=Path, required=True)
p.add_argument('--new-image', type=Path, required=True)
p.add_argument('--old-image', type=Path, required=True)
a = p.parse_args()
SIZE = 47185920
new = a.new_image.read_bytes()
old = a.old_image.read_bytes()
assert hashlib.sha256(new).hexdigest() == '947d409b9ffb819ab9920f5e5d468ba156c236dfc3a645020c1825ad1f7c9649'
assert hashlib.sha256(old).hexdigest() == '10c2c2ee77ee593ace840a12fb90145809e4521942b681bcee6e9c3b364370ed'
word = lambda y, m: (14 << 25) | ((y - 2000) << 4) | m  # Android 14.0.0
assert word(2026, 10) == struct.unpack_from('<I', new, 44)[0] == 0x1c0001aa
results = []

with tempfile.TemporaryDirectory(prefix='twrp21-sync-') as tmp:
    t = Path(tmp)
    bins = {}
    for tag, src in (('new', a.source), ('old', a.old_source)):
        bins[tag] = t / ('sync-' + tag)
        subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
                        '-DRECOVERY_HEADER_SYNC_HOST_TEST', str(src), '-lcrypto', '-o', str(bins[tag])], check=True)
    image, status = t / 'recovery.img', t / 'status'

    def reset(data):
        image.write_bytes(data + bytes(SIZE - len(data)))

    def run(mode, w, tag='new'):
        r = subprocess.run([str(bins[tag]), mode, hex(w), '--test-image', str(image), '--status-file', str(status)],
                           capture_output=True, text=True)
        st = status.read_text().strip() if status.exists() else ''
        if status.exists():
            status.unlink()
        return r.returncode, st, r.stdout + r.stderr

    def check(name, cond, detail=''):
        assert cond, (name, detail)
        results.append(name)

    # Preflight on the new image writes nothing.
    reset(new); before = image.read_bytes()
    rc, st, out = run('--preflight', word(2026, 10))
    check('new image preflight supported', rc == 0 and st == 'result=supported' and image.read_bytes() == before, out)
    rc, st, out = run('--apply', word(2026, 10))
    check('new image same level: no write', rc == 0 and st == 'result=synchronized' and image.read_bytes() == before, out)
    # Future OTAs: each applies the next ROM's patch level, the next one must still recognize it.
    current = before
    for y, m in ((2026, 11), (2026, 12), (2027, 6)):
        rc, st, out = run('--preflight', word(y, m))
        check('future %d-%02d preflight' % (y, m), rc == 0 and st == 'result=supported' and image.read_bytes() == current, out)
        rc, st, out = run('--apply', word(y, m))
        after = image.read_bytes()
        diff = [i for i in range(len(after)) if i < 64 and after[i] != current[i]]
        check('future %d-%02d apply' % (y, m), rc == 0 and st == 'result=synchronized'
              and struct.unpack_from('<I', after, 44)[0] == word(y, m) and after[48:] == current[48:]
              and after[:44] == current[:44] and set(diff) <= {44, 45, 46, 47}, out)
        current = after
    rc, st, out = run('--apply', word(2027, 5))
    check('downgrade refused, unchanged', rc != 0 and image.read_bytes() == current, out)
    rc, st, out = run('--preflight', (17 << 25) | (26 << 4) | 11)
    check('Android 17 word refused, unchanged', rc != 0 and image.read_bytes() == current, out)
    # Previous published LineageOS 21 TWRP still supported.
    reset(old); ob = image.read_bytes()
    rc, st, out = run('--preflight', word(2026, 11))
    check('previous TWRP 20261015 still supported', rc == 0 and st == 'result=supported' and image.read_bytes() == ob, out)
    rc, st, out = run('--apply', word(2026, 11))
    check('previous TWRP 20261015 synchronized', rc == 0 and st == 'result=synchronized'
          and struct.unpack_from('<I', image.read_bytes(), 44)[0] == word(2026, 11), out)
    # Tampered image: unsupported, kept, OTA continues (rc 0).
    bad = bytearray(new); bad[2048 * 100] ^= 1
    reset(bytes(bad)); bb = image.read_bytes()
    rc, st, out = run('--apply', word(2026, 11))
    check('modified image unsupported, unchanged, not blocked', rc == 0 and st == 'result=unsupported' and image.read_bytes() == bb, out)
    # Published 20261127 helper: new TWRP is unsupported (kept, install continues, no sync).
    reset(new)
    rc, st, out = run('--apply', word(2026, 11), 'old')
    check('20261127 helper: new TWRP unsupported, unchanged', rc == 0 and st == 'result=unsupported' and image.read_bytes()[:len(new)] == new, out)

print('\n'.join('PASS ' + r for r in results))
print('passed %d cases' % len(results))
