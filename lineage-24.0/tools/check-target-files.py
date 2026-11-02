#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only artifact checks for the diagnostic Android17 target-files package.

Checks selected image geometry/input hashes and multilib ELF headers. This is
not filesystem, security, installer, runtime or flash-readiness approval.
Use only after the full build and its after-audit have completed.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import struct
import sys
import tempfile
import zipfile

SIZES = {'boot.img': 33554432, 'recovery.img': 47185920,
         'system.img': 3196059648, 'vendor.img': 343932928,
         'product.img': 327155712, 'cache.img': 159383552}
INPUTS = {'vendor.img': 'a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a',
          'dtbo.img': 'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b'}
KERNEL = '33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['top', 'archive', 'snapshot', 'source-audit', 'build-exit', 'report']:
        p.add_argument('--'+name, required=True, type=Path)
    args = p.parse_args()
    top, archive, snapshot, audit, report = [x.resolve() for x in
        [args.top, args.archive, args.snapshot, args.source_audit, args.report]]
    require(not report.exists() and not report.is_relative_to(top) and
            not report.is_relative_to(snapshot), 'Report must be fresh and outside protected source')
    require(args.build_exit.read_text().strip() == '0', 'Full build did not finish successfully')
    require(audit.name == 'source-audit-after.json', 'Use the successful build after-audit')
    source = json.loads(audit.read_text())
    require(source['passed'] and source['manifest_sha256'] == digest(snapshot/'port-manifest.xml'),
            'Missing/mismatched successful source after-audit')
    # Import the actual source-bound AOSP sparse image parser, rather than
    # trusting only the claimed expansion count in an unparsed sparse header.
    sys.path.insert(0, str(top/'build/make/tools/releasetools'))
    import sparse_img
    result = {'scope': 'Diagnostic package geometry, input identity and selected ELF checks only',
              'archive': str(archive), 'archive_sha256': digest(archive),
              'source_after_audit_sha256': digest(audit), 'images': {}, 'elfs': {},
              'build_exit_file_sha256': digest(args.build_exit),
              'hardware_tested': False, 'flash_ready': False,
              'installer_or_security_approved': False,
              'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    with zipfile.ZipFile(archive) as z, tempfile.TemporaryDirectory(
            prefix='target-files-check-', dir=report.parent) as scratch:
        names = z.namelist()
        require(len(names) == len(set(names)), 'Duplicate archive members')
        for name in names:
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts, 'Unsafe archive path')
            # Do not read or copy private signing material if mispackaged.
            require(not name.endswith(('.pk8', '.p12', '.pfx', '.key')) and
                    not (name.endswith('.pem') and not name.endswith('.x509.pem')),
                    'Unexpected private-key candidate in archive: '+name)
        require('IMAGES/userdata.img' not in names, 'Unexpected userdata image')
        props = dict(line.split('=', 1) for line in z.read('SYSTEM/build.prop').decode().splitlines()
                     if '=' in line and not line.startswith('#'))
        require(props['ro.build.version.release'] in ('17', '17.0', '17.0.0'), 'Not Android17')
        patch = datetime.date.fromisoformat(props['ro.build.version.security_patch'])
        require(2020 <= patch.year <= 2127, 'Unrepresentable boot security patch year')
        expected_word = (17 << 25) | ((patch.year-2000) << 4) | patch.month
        result['android_release'] = props['ro.build.version.release']
        result['security_patch'] = str(patch)
        for name in [*SIZES, 'dtbo.img']:
            image = Path(scratch)/name
            with z.open('IMAGES/'+name) as src, image.open('wb') as dst:
                shutil.copyfileobj(src, dst, 1024*1024)
            sha = digest(image)
            if name in INPUTS:
                require(sha == INPUTS[name], 'Reviewed binary input differs: '+name)
            with image.open('rb') as f:
                header = f.read(2048)
            sparse = header[:4] == struct.pack('<I', 0xed26ff3a)
            expanded = image.stat().st_size
            if sparse:
                parsed = sparse_img.SparseImage(str(image), clobbered_blocks='0')
                expanded = parsed.blocksize * parsed.total_blocks
                parsed.simg_f.close()
            if name in SIZES:
                require(expanded <= SIZES[name], 'Image exceeds physical partition: '+name)
            if name in ('system.img', 'product.img', 'vendor.img', 'cache.img'):
                require(expanded == SIZES[name], 'Unexpected filesystem geometry: '+name)
            entry = {'bytes': image.stat().st_size, 'expanded_bytes': expanded,
                     'sha256': sha, 'sparse': sparse}
            if name in ('boot.img', 'recovery.img'):
                board = b'SRPSA25A005KU' if name == 'boot.img' else b'SRPSA25A005RU'
                require(header[:8] == b'ANDROID!' and len(header) == 2048 and
                        struct.unpack_from('<I', header, 36)[0] == 2048 and
                        struct.unpack_from('<I', header, 40)[0] == 1 and
                        header[48:64].rstrip(b'\0') == board, 'Unexpected Samsung boot header')
                kernel_bytes = struct.unpack_from('<I', header, 8)[0]
                require(0 < kernel_bytes <= image.stat().st_size-2048, 'Invalid embedded kernel bounds')
                with image.open('rb') as f:
                    f.seek(2048)
                    kernel_sha = hashlib.sha256(f.read(kernel_bytes)).hexdigest()
                    marker = b'SEANDROIDENFORCE'
                    f.seek(-len(marker), 2)
                    require(f.read() == marker, 'Missing Samsung trailer: '+name)
                require(kernel_sha == KERNEL, 'Unreviewed kernel in '+name)
                ramdisk_bytes = struct.unpack_from('<I', header, 16)[0]
                require((name == 'boot.img' and ramdisk_bytes == 0) or
                        (name == 'recovery.img' and ramdisk_bytes > 0),
                        'Unexpected system-as-root/recovery ramdisk shape')
                entry['kernel_sha256'] = kernel_sha
                entry['os_version_word'] = struct.unpack_from('<I', header, 44)[0]
                require(entry['os_version_word'] == expected_word, 'Boot header/build properties disagree')
            result['images'][name] = entry
        for bits, directory, elf_class, machine in [(32, 'lib', 1, 40), (64, 'lib64', 2, 183)]:
            for lib in ['libaudiohal@4.0.so', 'libprocessgroup.so', 'libmeminfo.so', 'libfs_mgr.so']:
                name = 'SYSTEM/'+directory+'/'+lib
                data = z.read(name)
                require(len(data) >= 52 and data[:4] == b'\x7fELF' and data[4] == elf_class and
                        data[5] == 1 and struct.unpack_from('<H', data, 18)[0] == machine,
                        'Incorrect ELF architecture: '+name)
                result['elfs'][name] = {'bits': bits, 'sha256': hashlib.sha256(data).hexdigest()}
        result['selected_zip_entries_crc_checked'] = True
        result['whole_archive_crc_checked'] = False
        result['artifact_checks_passed'] = True
    report.write_text(json.dumps(result, indent=2)+'\n')
    print('Selected artifact checks PASS; this is NOT flash-readiness approval.')


if __name__ == '__main__':
    main()
