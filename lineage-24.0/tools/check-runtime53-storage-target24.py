#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the snapshot53 SD-card storage change (issue 4) to the actual target files.

Usage: check-runtime53-storage-target24.py TOP ARCHIVE GEOMETRY EDITS KERNEL_BUILD OUTPUT

Requires: the product makefile and releasetools.py equal the staged after-hashes;
the packaged build props define ro.crypto.volume.options exactly once, as
aes-256-xts:aes-256-cts:v1, and persist.sys.adoptable exactly once, as force_on, with
no other ro.crypto.volume.* definition; the kernel the build selected accepts that
mode pair for F2FS (fscrypt_valid_enc_modes XTS/CTS) and has no HEH support in the
generic fscrypt path; vold's parser knows both mode names and the pre-Q HEH default
that the property overrides; the packaged boot.img kernel is the sdfat-exfat Image
whose build proved the "exfat" file_system_type symbol; the packaged releasetools.py
guards that digest and no longer the previous one. Package check only; physical
adoptable/exFAT mounting requires the device test.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile

top, archive, geometry, edits, kernel_build, output = map(Path, sys.argv[1:])
assert not output.exists()


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


g = json.loads(geometry.read_text())
assert g['artifact_checks_passed'] and sha(archive) == g['archive_sha256']
e = json.loads(edits.read_text())
dev = top/'device/samsung/gta3xlwifi'
assert set(e) == {str(dev/'releasetools.py'), str(dev/'lineage_gta3xlwifi.mk')}
for name, meta in e.items():
    assert sha(Path(name)) == meta['after_sha256'], name
k = json.loads((kernel_build/'report.json').read_text())
assert k['passed'] and k['host_sdfat_exfat_cases'] == 10 and k['kernel_config_identical_to_active']
symbols = (kernel_build/'vmlinux-symbols.txt').read_text().splitlines()
assert any(l.endswith((' d exfat_fs_type', ' D exfat_fs_type')) for l in symbols), 'no exfat_fs_type in vmlinux'
assert sha(dev/'prebuilt/Image') == k['Image_sha256']
ksrc = Path('/srv/android/ports/lineage-24.0-arm64/kernel-sdfat-exfat-20261123-01/src')
priv = (ksrc/'fs/crypto/fscrypt_private.h').read_text()
assert ('if (contents_mode == FS_ENCRYPTION_MODE_AES_256_XTS &&\n'
        '\t    filenames_mode == FS_ENCRYPTION_MODE_AES_256_CTS)\n\t\treturn true;') in priv
assert 'HEH' not in priv and 'HEH' not in (ksrc/'include/uapi/linux/fs.h').read_text()
fscrypt = (top/'system/vold/FsCrypt.cpp').read_text()
assert '"ro.crypto.volume.options"' in fscrypt and '"aes-256-heh"' in fscrypt
names = (top/'system/extras/libfscrypt/fscrypt.cpp').read_text()
assert '"aes-256-xts"' in names and '"aes-256-cts"' in names
WANT = {'ro.crypto.volume.options': 'aes-256-xts:aes-256-cts:v1', 'persist.sys.adoptable': 'force_on'}
seen = {}
result = {'passed': False}
with zipfile.ZipFile(archive) as z:
    for name in z.namelist():
        if not (name.endswith('build.prop') or name.endswith('/default.prop') or name.endswith('.prop')):
            continue
        for line in z.read(name).decode(errors='replace').splitlines():
            if '=' not in line or line.startswith('#'):
                continue
            key, value = line.split('=', 1)
            if key in WANT or key.startswith('ro.crypto.volume.'):
                seen.setdefault(key, []).append((name, value))
    assert set(seen) == set(WANT), seen
    for key, value in WANT.items():
        assert [v for _, v in seen[key]] == [value], (key, seen[key])
    boot = z.read('IMAGES/boot.img')
    kb = struct.unpack_from('<I', boot, 8)[0]
    boot_kernel = hashlib.sha256(boot[2048:2048+kb]).hexdigest()
    assert boot_kernel == k['Image_sha256'], 'boot kernel is not the sdfat-exfat Image'
    tools = z.read('META/releasetools.py')
    assert tools == (dev/'releasetools.py').read_bytes()
    assert tools.count(k['Image_sha256'].encode()) == 1 and k['previous_Image_sha256'].encode() not in tools
result.update(passed=True, archive_sha256=g['archive_sha256'], props={k2: v[0][0] for k2, v in seen.items()},
              boot_kernel_sha256=boot_kernel, kernel_build_report_sha256=sha(kernel_build/'report.json'),
              edits_sha256=sha(edits), vendor_image_changed=False, adoptable_mount_tested=False,
              exfat_mount_tested=False, flash_ready=False)
output.write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
print('PASS SD-card storage props, sdfat-exfat boot kernel and OTA kernel guard')
