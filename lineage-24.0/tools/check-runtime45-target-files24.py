#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only artifact checks for the composed Android17 target-files package and explicitly selected runtime pair.

Checks selected image geometry/input hashes and multilib ELF headers. This is
not filesystem, security, installer, runtime or flash-readiness approval.
Use only after the full build and its after-audit have completed.

Runtime38 variant (only change): the boot.img header OS patch level must equal
the fixed --boot-security-patch level (BoardConfig.mk BOOT_SECURITY_PATCH), and
the system ro.build.version.security_patch must not be older. The generated
recovery.img (never written by the installer) keeps the platform level.

Runtime40 variant (only change): /product is folded into /system (snapshot40);
no product image, product members live under SYSTEM/product/. Product sepolicy
inputs recorded by the strict report are mapped to system/product with identical
content, and the misc_info/target-files must contain no product image.
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
         'cache.img': 159383552}


# Runtime45: snapshot45 (releasetools only); compared with build 44 the file set must be identical.
STALE_REFERENCE = Path('/srv/android/artifacts/lineage-24.0-arm64/runtime44-ota-build-20261121-01/target-files.zip')
STALE_OR_PRODUCT_ONLY_IN_39 = set()


def moved(path):
    """Map a recorded separate-product output path to system/product (snapshot40)."""
    s = str(path); old = '/out/target/product/gta3xlwifi/product/'
    if old not in s:
        return Path(s)
    require(not Path(s).exists(), 'Stale separate product output still present: '+s)
    return Path(s.replace(old, '/out/target/product/gta3xlwifi/system/product/'))


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def check_ota_layout(archive, props):
    """Physical non-A/B contract; default COW version alone is not enablement."""
    info = dict(line.split('=', 1) for line in archive.read('META/misc_info.txt').decode().splitlines()
                if '=' in line and not line.startswith('#'))
    require(info.get('ab_update') != 'true', 'A/B OTA metadata on physical non-A/B device')
    require(info.get('allow_non_ab') == 'true', 'Non-A/B OTA support is not enabled')
    require(info.get('gta3xlwifi_preserve_recovery') == 'true', 'Recovery preservation is not declared')
    require(not info.get('multistage_support'), 'Recovery-replacing multistage OTA is enabled')
    for key in ['use_dynamic_partitions', 'virtual_ab', 'virtual_ab_retrofit']:
        require(info.get(key) != 'true', 'Unsupported partition scheme: '+key)
    for key in ['ro.build.ab_update', 'ro.virtual_ab.enabled', 'ro.boot.dynamic_partitions']:
        require(props.get(key) != 'true', 'Unsupported partition property: '+key)
    require('META/ab_partitions.txt' not in archive.namelist(), 'Unexpected A/B partition list')
    require('META/dynamic_partitions_info.txt' not in archive.namelist(), 'Unexpected dynamic partition metadata')
    require(info.get('building_product_image') != 'true' and 'product_size' not in info and
            'product_fs_type' not in info, 'Product image still configured')
    require('IMAGES/product.img' not in archive.namelist() and
            not any(n.startswith('PRODUCT/') for n in archive.namelist()), 'Separate product partition content')
    require(any(n.startswith('SYSTEM/product/etc/') for n in archive.namelist()), 'Missing system/product')
    for name in archive.namelist():
        require(not name.endswith(('/install-recovery.sh', '/recovery-from-boot.p',
                                   '/recovery-resource.dat', '/vendor_flash_recovery.rc')),
                'Automatic recovery replacement resource: '+name)
        require(name not in ('VENDOR/etc/recovery.img', 'SYSTEM/vendor/etc/recovery.img'),
                'Automatic recovery replacement image: '+name)
    return {'product_folded_into_system': True, 'physical_non_ab': True, 'allow_non_ab': True, 'dynamic_partitions': False,
            'recovery_replacement_resources_absent': True, 'recovery_preservation_declared': True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['top', 'archive', 'snapshot', 'source-audit', 'build-exit', 'report', 'input-selection', 'strict-report', 'vendor-report']:
        p.add_argument('--'+name, required=True, type=Path)
    p.add_argument('--boot-security-patch', required=True, type=datetime.date.fromisoformat)
    args = p.parse_args()
    top, archive, snapshot, audit, report = [x.resolve() for x in
        [args.top, args.archive, args.snapshot, args.source_audit, args.report]]
    require(not report.exists() and not report.is_relative_to(top) and
            not report.is_relative_to(snapshot), 'Report must be fresh and outside protected source')
    require(args.build_exit.read_text().strip() == '0', 'Full build did not finish successfully')
    require(audit.name == 'source-after.json' and audit.parent.name == args.build_exit.stem, 'Use this successful build after-audit')
    source = json.loads(audit.read_text())
    require(source['passed'] and source['manifest_sha256'] == digest(snapshot/'port-manifest.xml'),
            'Missing/mismatched successful source after-audit')
    expected_source=json.loads((snapshot/'port-audit.json').read_text())
    require(source['projects']==expected_source['projects'] and source['reviewed_patch_count']==expected_source['reviewed_patch_count'], 'Source patch inventory differs from the exact selected snapshot')
    selection=json.loads(args.input_selection.read_text())
    require(selection['passed'] and selection['original_rollback_copies_verified'], 'Missing explicit runtime selection')
    for f in [args.strict_report,args.vendor_report]:
        require(selection['proofs_sha256'][str(f.resolve())]==digest(f),'Mismatched runtime proof')
    strict=json.loads(args.strict_report.read_text());vendor=json.loads(args.vendor_report.read_text())
    require(strict['passed_strict'] and not strict['explicit_input_overrides'] and vendor['passed'], 'Strict composition required')
    expected_inputs={n:selection['after'][n] for n in ['vendor.img','dtbo.img']}
    expected_kernel=selection['after']['Image']
    require(selection['source_snapshot']==str(snapshot),'Different runtime source snapshot')
    # The original runner emitted a literal backslash-n trailer in these two
    # metadata files. Accept only that exact formatting defect or a real newline;
    # validate every field and retain raw file digests. No artifact is rewritten.
    for name in ['inputs-before.json','inputs-after.json']:
        f=audit.parent/name;raw=f.read_text();value,end=json.JSONDecoder().raw_decode(raw)
        require(raw[end:] in ('\n','\\n'),'Unexpected input audit trailer')
        require(value['selection_report_sha256']==digest(args.input_selection) and value['prebuilts']==selection['after'],'Runtime inputs drifted during build')
    # Import the actual source-bound AOSP sparse image parser, rather than
    # trusting only the claimed expansion count in an unparsed sparse header.
    sys.path.insert(0, str(top/'build/make/tools/releasetools'))
    sys.dont_write_bytecode = True
    import sparse_img
    result = {'scope': 'Diagnostic package geometry, input identity and selected ELF checks only',
              'archive': str(archive), 'archive_sha256': digest(archive),
              'source_after_audit_sha256': digest(audit), 'images': {}, 'elfs': {},
              'build_exit_file_sha256': digest(args.build_exit),
              'source_lock_sha256':digest(snapshot/'source-lock.json'),
              'input_audits_sha256':{name:digest(audit.parent/name) for name in ['inputs-before.json','inputs-after.json']},
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
        result['ota_layout'] = check_ota_layout(z, props)
        patch = datetime.date.fromisoformat(props['ro.build.version.security_patch'])
        require(2020 <= patch.year <= 2127, 'Unrepresentable boot security patch year')
        expected_word = (17 << 25) | ((patch.year-2000) << 4) | patch.month
        boot_patch = args.boot_security_patch
        require(2020 <= boot_patch.year <= 2127, 'Unrepresentable boot security patch year')
        require((patch.year, patch.month) >= (boot_patch.year, boot_patch.month),
                'System patch level is older than the fixed boot patch level')
        boot_word = (17 << 25) | ((boot_patch.year-2000) << 4) | boot_patch.month
        result['android_release'] = props['ro.build.version.release']
        result['security_patch'] = str(patch)
        result['boot_security_patch'] = str(boot_patch)
        result['boot_os_version_word'] = boot_word
        for name in [*SIZES, 'dtbo.img']:
            image = Path(scratch)/name
            with z.open('IMAGES/'+name) as src, image.open('wb') as dst:
                shutil.copyfileobj(src, dst, 1024*1024)
            sha = digest(image)
            if name in expected_inputs:
                require(sha == expected_inputs[name], 'Reviewed binary input differs: '+name)
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
            if name in ('system.img', 'vendor.img', 'cache.img'):
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
                require(kernel_sha == expected_kernel, 'Unreviewed kernel in '+name)
                ramdisk_bytes = struct.unpack_from('<I', header, 16)[0]
                require((name == 'boot.img' and ramdisk_bytes == 0) or
                        (name == 'recovery.img' and ramdisk_bytes > 0),
                        'Unexpected system-as-root/recovery ramdisk shape')
                entry['kernel_sha256'] = kernel_sha
                entry['os_version_word'] = struct.unpack_from('<I', header, 44)[0]
                require(entry['os_version_word'] == (boot_word if name == 'boot.img' else expected_word),
                        'Boot header/fixed boot level or recovery header/build properties disagree')
            result['images'][name] = entry
        # Runtime40 builds after m installclean. Build 39's system carried stale earlier
        # installs (32-bit libfs_mgr and friends, bin/updater, bin/linkerconfig; the
        # runtime APEX provides linkerconfig). Require the exact file-set difference
        # and probe libfs_mgr only where it is really built (lib64).
        with zipfile.ZipFile(STALE_REFERENCE) as old:
            norm = lambda n: 'SYSTEM/product/'+n[len('PRODUCT/'):] if n.startswith('PRODUCT/') else n
            before = {norm(i.filename) for i in old.infolist() if not i.is_dir()}
        after = {i.filename for i in z.infolist() if not i.is_dir()}
        require(before - after == STALE_OR_PRODUCT_ONLY_IN_39, 'Unexpected file removal vs build 39: '+str(sorted(before-after)))
        require(after - before == set(), 'Unexpected file addition vs build 44: '+str(sorted(after-before)))
        result['removed_stale_vs_build39'] = sorted(STALE_OR_PRODUCT_ONLY_IN_39)
        for bits, directory, elf_class, machine in [(32, 'lib', 1, 40), (64, 'lib64', 2, 183)]:
            for lib in ['libaudiohal@4.0.so', 'libprocessgroup.so', 'libmeminfo.so'] + (['libfs_mgr.so'] if bits == 64 else []):
                name = 'SYSTEM/'+directory+'/'+lib
                data = z.read(name)
                require(len(data) >= 52 and data[:4] == b'\x7fELF' and data[4] == elf_class and
                        data[5] == 1 and struct.unpack_from('<H', data, 18)[0] == machine,
                        'Incorrect ELF architecture: '+name)
                result['elfs'][name] = {'bits': bits, 'sha256': hashlib.sha256(data).hexdigest()}
        policy_members={}
        base=top/'out/target/product/gta3xlwifi'
        for item in strict['inputs']:
            path=moved(Path(item['path']))
            if path.is_relative_to(base/'system'):
                member='SYSTEM/'+str(path.relative_to(base/'system'))
            else:
                require(path.name in ['plat_pub_versioned.cil','vendor_sepolicy.cil'],'Unreviewed external policy input')
                continue
            require(hashlib.sha256(z.read(member)).hexdigest()==item['sha256'],'Packaged policy input differs: '+member)
            policy_members[member]=item['sha256']
        for prefix,part in [('SYSTEM/etc/selinux/','plat'),('SYSTEM/system_ext/etc/selinux/','system_ext'),('SYSTEM/product/etc/selinux/','product')]:
            name=part+'_sepolicy_and_mapping.sha256'
            expected=vendor['changed_paths']['/etc/selinux/precompiled_sepolicy.'+name]
            require(hashlib.sha256(z.read(prefix+name)).hexdigest()==expected,'Packaged policy cache identity differs')
        result['strict_policy_members']=policy_members
        result['runtime_input_selection_sha256']=digest(args.input_selection)
        result['strict_policy_report_sha256']=digest(args.strict_report)
        result['vendor_composition_report_sha256']=digest(args.vendor_report)
        result['selected_zip_entries_crc_checked'] = True
        result['whole_archive_crc_checked'] = False
        result['artifact_checks_passed'] = True
    report.write_text(json.dumps(result, indent=2)+'\n')
    print('Selected artifact checks PASS; this is NOT flash-readiness approval.')


if __name__ == '__main__':
    main()
