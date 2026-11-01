#!/usr/bin/env python3
"""Produce an isolated MTP vendor candidate; never modify the release input."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

BASELINE_SHA256 = '276777b5bde1dac2f31dbe9299c79e02c07486df6ff7b2ecad03cc722edee939'
STOCK_RC_SHA256 = '63f9119a81270ee2a6ce319d6d58e91fe9eccdfd4f1bbe2c2f7cdb2dde7922cf'
RC = 'etc/init/init.exynos7904.usb.rc'
BYTES = 343932928

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def inventory(root):
    result = {}
    for p in sorted(root.rglob('*')):
        st = p.lstat()
        value = {'mode': st.st_mode, 'uid': st.st_uid, 'gid': st.st_gid,
                 'xattrs': {k: os.getxattr(p, k, follow_symlinks=False).hex()
                            for k in os.listxattr(p, follow_symlinks=False)}}
        if p.is_symlink():
            value['symlink'] = os.readlink(p)
        elif p.is_file():
            value['sha256'] = sha(p)
        result[str(p.relative_to(root))] = value
    return result

def run(*args):
    subprocess.run(args, check=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path, help='Reviewed sparse ARM64 vendor image')
    parser.add_argument('--output', required=True, type=Path, help='New, nonexistent directory')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root to preserve ownership and SELinux xattrs')
    source = args.input.resolve(strict=True)
    if sha(source) != BASELINE_SHA256:
        parser.error('Input is not the reviewed October 15 ARM64 vendor')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    replacement = Path(__file__).resolve().parents[1] / 'configs/init.exynos7904.usb.rc'
    raw, sparse = output / 'vendor.raw.img', output / 'vendor.img'
    run('simg2img', str(source), str(raw))
    if raw.stat().st_size != BYTES:
        raise RuntimeError('Wrong physical vendor size')
    with tempfile.TemporaryDirectory(prefix='mtp-vendor-') as temp:
        mount = Path(temp)
        run('mount', '-o', 'loop,rw', str(raw), str(mount))
        try:
            before = inventory(mount)
            if before[RC]['sha256'] != STOCK_RC_SHA256:
                raise RuntimeError('Unexpected original USB init script')
            # Truncate in place: retain the original inode's label, mode and owner.
            (mount / RC).write_bytes(replacement.read_bytes())
            after = inventory(mount)
            expected = dict(before[RC], sha256=sha(replacement))
            if after[RC] != expected:
                raise RuntimeError('USB init metadata changed')
            differences = [p for p in before.keys() | after.keys()
                           if before.get(p) != after.get(p)]
            if differences != [RC]:
                raise RuntimeError(f'Unexpected filesystem changes: {differences}')
        finally:
            run('umount', str(mount))
    run('e2fsck', '-f', '-n', str(raw))
    run('img2simg', str(raw), str(sparse))
    report = {'baseline_sparse_sha256': BASELINE_SHA256,
              'sparse_sha256': sha(sparse), 'raw_sha256': sha(raw),
              'physical_bytes': BYTES, 'changed_files': differences,
              'rc_sha256': sha(replacement), 'file_metadata_preserved': True,
              'other_files_and_directories_unchanged': True,
              'hardware_tested': False, 'release_ota_hash_not_promoted': True}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
