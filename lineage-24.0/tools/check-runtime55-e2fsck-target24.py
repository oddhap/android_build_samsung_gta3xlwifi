#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged e2fsck to the snapshot55 issue #6 fix and exercise the compiled check.

Usage: check-runtime55-e2fsck-target24.py TOP ARCHIVE GEOMETRY EDITS REFERENCE MKIMG IMGTOOLS OUTPUT

Requires:
- the staged e2fsck/encrypted_files.c equals its after-hash (edits.json);
- SYSTEM/bin/e2fsck in the checked archive equals out/.../system/bin/e2fsck and differs
  from build 54 (REFERENCE target-files); the recovery ramdisk copy equals the built recovery
  variant and also differs from build 54;
- out/host/linux-x86/bin/e2fsck (rebuilt from the same patched tree by the product build)
  on synthetic ext4 images made by MKIMG with independent stock tools IMGTOOLS
  (mke2fs/debugfs build tree):
  * Samsung case (dir ctx 01 7f 04 00, file ctx 01 7f 04 04): -fn clean (exit 0),
    -fy changes nothing (exit 0), lost+found stays empty;
  * control (equal modes 9/9, file flags 0x04 = real mismatch): -fn still reports
    2 "different encryption policy" errors (upstream checking not weakened).
Package/host check only; the device test is separate.
"""
import hashlib, json, re, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path

top, archive, geometry, edits, reference, mkimg, imgtools, output = map(Path, sys.argv[1:])
assert not output.exists()
sha = lambda b: hashlib.sha256(b).hexdigest()
g = json.loads(geometry.read_text())
assert g['artifact_checks_passed']
h = hashlib.sha256()
with archive.open('rb') as f:
    for block in iter(lambda: f.read(1 << 20), b''):
        h.update(block)
assert h.hexdigest() == g['archive_sha256'], 'Archive differs from the checked geometry report'
e = json.loads(edits.read_text())
src = top/'external/e2fsprogs/e2fsck/encrypted_files.c'
assert list(e) == [str(src)]
assert sha(src.read_bytes()) == e[str(src)]['after_sha256']
with zipfile.ZipFile(archive) as z:
    packaged = z.read('SYSTEM/bin/e2fsck')
    rec = z.read('RECOVERY/RAMDISK/system/bin/e2fsck')
with zipfile.ZipFile(reference) as z:
    old = z.read('SYSTEM/bin/e2fsck')
    old_rec = z.read('RECOVERY/RAMDISK/system/bin/e2fsck')
built = (top/'out/target/product/gta3xlwifi/system/bin/e2fsck').read_bytes()
assert packaged == built, 'Packaged e2fsck differs from the built one'
assert packaged != old, 'Packaged e2fsck unchanged from build 54'
# The recovery ramdisk carries the separately built recovery variant (it already differed
# from the system copy in build 54); it is never written by the installer, but must also be
# the rebuilt one.
assert rec == (top/'out/target/product/gta3xlwifi/recovery/root/system/bin/e2fsck').read_bytes()
assert rec != old_rec, 'Recovery e2fsck unchanged from build 54'
host = top/'out/host/linux-x86/bin/e2fsck'
assert host.stat().st_mtime > src.stat().st_mtime, 'Host e2fsck older than the patched source'
res = {}
with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    def make(name, control):
        script = mkimg.read_text()
        if control:
            script = script.replace('017f0400', '01090900').replace('017f0404', '01090904')
        (d/(name+'.sh')).write_text(script)
        subprocess.run(['bash', str(d/(name+'.sh')), str(imgtools), str(d/(name+'.img'))],
                       check=True, capture_output=True)
        return d/(name+'.img')
    def fsck(img, flag):
        r = subprocess.run([str(host), flag, str(img)], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr
    sam = make('samsung', False)
    rc, out = fsck(sam, '-fn')
    res['samsung_fn'] = {'exit': rc, 'policy_errors': out.count('different encryption policy')}
    shutil.copy(sam, d/'samsung-y.img')
    rc, out = fsck(d/'samsung-y.img', '-fy')
    lf = subprocess.run([str(imgtools/'debugfs/debugfs'), '-R', 'ls /lost+found', str(d/'samsung-y.img')],
                        capture_output=True, text=True).stdout
    res['samsung_fy'] = {'exit': rc, 'modified': 'MODIFIED' in out,
                         'lost_found_entries': len(re.findall(r'#\d+', lf))}
    rc, out = fsck(make('control', True), '-fn')
    res['control_fn'] = {'exit': rc, 'policy_errors': out.count('different encryption policy')}
assert res['samsung_fn'] == {'exit': 0, 'policy_errors': 0}, res
assert res['samsung_fy'] == {'exit': 0, 'modified': False, 'lost_found_entries': 0}, res
assert res['control_fn']['policy_errors'] == 2 and res['control_fn']['exit'] == 4, res
output.write_text(json.dumps({'passed': True,
                              'imgtools_sha256': {n: sha((imgtools/n).read_bytes()) for n in ['misc/mke2fs', 'debugfs/debugfs']},
                              'system_e2fsck_sha256': sha(packaged),
                              'recovery_e2fsck_sha256': sha(rec),
                              'build54_e2fsck_sha256': sha(old),
                              'host_e2fsck_sha256': sha(host.read_bytes()),
                              'encrypted_files_c_after_sha256': e[str(src)]['after_sha256'],
                              'host_results': res,
                              'runtime_tested': False}, indent=2)+'\n')
print('PASS e2fsck Samsung policy flag packaged and host-exercised:', output)
