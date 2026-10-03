#!/usr/bin/env python3
"""Verify private APK/APEX signatures, OTA signature and tested device layout."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('original', type=Path)
parser.add_argument('--release', type=Path, default=Path('/srv/android/artifacts/lineage-21/release'))
parser.add_argument('--keys', type=Path, default=Path('/srv/android/signing/gta3xlwifi'))
args = parser.parse_args()
top = Path('/srv/android/src/lineage-21.0')
host = top / 'out/host/linux-x86/bin'
env = os.environ.copy()
env['PATH'] = str(host) + ':' + str(top / 'prebuilts/jdk/jdk17/linux-x86/bin') + ':' + env['PATH']
mapping = json.loads((args.keys / 'certificate-map.json').read_text())
certificates = {m['old_path'] + '.x509.pem': m for m in mapping}
checks = {'hardware_tested': False}

def run(command, **kwargs):
    return subprocess.run(command, check=True, env=env, capture_output=True, **kwargs).stdout

def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()

def parse(text):
    return [dict(re.findall(r'(\w+)="([^"]*)"', line)) for line in text.splitlines() if line]

with tempfile.TemporaryDirectory(dir=args.release, prefix='verify-') as tmp:
    temp = Path(tmp)
    with zipfile.ZipFile(args.original) as old, zipfile.ZipFile(args.release / 'signed-target-files.zip') as new:
        assert new.testzip() is None
        apkkeys = {x['name']: x for x in parse(old.read('META/apkcerts.txt').decode())}
        apexkeys = {x['name']: x for x in parse(old.read('META/apexkeys.txt').decode())}
        tasks, apexes = [], []
        preserved = 0
        for member in new.namelist():
            if not member.endswith(('.apk', '.apk.gz', '.apex', '.capex')):
                continue
            basename = Path(member).name.removesuffix('.gz').replace('.capex', '.apex')
            is_apex = member.endswith(('.apex', '.capex'))
            info = (apexkeys if is_apex else apkkeys)[basename]
            cert = info['container_certificate' if is_apex else 'certificate']
            data = new.read(member)
            if member.startswith('VENDOR/') or cert in ('PRESIGNED', 'EXTERNAL'):
                assert data == old.read(member), member + ' changed unexpectedly'
                preserved += 1
                continue
            if member.endswith('.gz'):
                data = gzip.decompress(data)
            path = temp / basename
            path.write_bytes(data)
            if member.endswith('.capex'):
                with zipfile.ZipFile(path) as compressed:
                    path.write_bytes(compressed.read('original_apex'))
            tasks.append((path, certificates[cert]['new_sha256']))
            if is_apex:
                apexes.append((path, basename))

        def check_certificate(task):
            path, expected = task
            result = run(['apksigner', 'verify', '--print-certs', str(path)]).decode()
            actual = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)', result)
            assert actual == [expected], str(path) + ' unexpected APK certificate'
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(check_certificate, tasks))
        checks['verified_private_apk_and_apex_container_signatures'] = len(tasks)
        checks['presigned_or_stock_vendor_packages_preserved'] = preserved
        for path, basename in apexes:
            payload = args.keys / ('payload-' + basename.removesuffix('.apex') + '.pem')
            expected_public = temp / 'expected.avbpubkey'
            run(['avbtool', 'extract_public_key', '--key', str(payload), '--output', str(expected_public)])
            with zipfile.ZipFile(path) as apex:
                assert apex.read('apex_pubkey') == expected_public.read_bytes()
                image = temp / 'apex-payload.img'
                image.write_bytes(apex.read('apex_payload.img'))
            run(['avbtool', 'verify_image', '--image', str(image), '--key', str(payload)])
        checks['verified_private_apex_payload_signatures'] = len(apexes)
        assert new.read('IMAGES/boot.img') == old.read('IMAGES/boot.img')
        checks['boot_image_preserved'] = True
        tree = args.release / 'verified-target-files'
        tree.mkdir(exist_ok=True)
        new.extractall(tree)
        images = {}
        for name, limit in [('system.img',3196059648), ('product.img',327155712), ('boot.img',33554432)]:
            path = tree / 'IMAGES' / name
            with path.open('rb') as stream:
                header = stream.read(28)
            expanded = struct.unpack_from('<I', header,12)[0] * struct.unpack_from('<I', header,16)[0] if header[:4] == b'\x3a\xff\x26\xed' else path.stat().st_size
            assert expanded <= limit
            images[name] = {'path':str(path), 'sha256':sha(path), 'expanded_bytes':expanded, 'partition_bytes':limit}
        for member in ('SYSTEM/lib/libmeminfo.so', 'SYSTEM/bin/netd', 'SYSTEM/lib/libgpuwork.so',
                       'SYSTEM/lib/libaudiohal@4.0.so', 'SYSTEM/system_ext/etc/selinux/system_ext_sepolicy.cil'):
            assert new.read(member) == old.read(member), member + ' changed during signing'
        checks['tested_platform_fixes_preserved'] = True
        props = new.read('SYSTEM/build.prop').decode()
        assert 'ro.build.tags=release-keys\n' in props and 'ro.build.type=userdebug\n' in props
        version = re.search(r'^ro.lineage.version=(21\.0-[0-9]{8}-UNOFFICIAL-gta3xlwifi)$', props, re.M).group(1)
        checks['build_tags'] = 'release-keys'
        checks['build_type'] = 'userdebug'

    ota = args.release / ('lineage-' + version + '-privatekeys.zip')
    with zipfile.ZipFile(ota) as archive:
        assert archive.testzip() is None
        metadata = archive.read('META-INF/com/android/metadata').decode()
        assert 'pre-device=gta3xlwifi' in metadata.splitlines()
        assert '/release-keys' in metadata
        assert 'ota-wipe=yes' not in metadata
        script = archive.read('META-INF/com/google/android/updater-script').decode()
        partitions = set(re.findall(r'/dev/block/platform/13500000\.dwmmc0/by-name/([a-zA-Z0-9_]+)', script))
        assert partitions == {'system', 'product', 'boot'}, partitions
        assert 'format(' not in script and 'delete_recursive("/data' not in script
        assert archive.read('boot.img') == (tree / 'IMAGES/boot.img').read_bytes()
    with ota.open('rb') as stream:
        stream.seek(-6,2)
        start, magic, comment = struct.unpack('<H2sH',stream.read())
        assert magic == b'\xff\xff' and start <= comment
        signed_length = ota.stat().st_size - comment - 2
        stream.seek(-start,2)
        signature = temp / 'ota-signature.der'
        signature.write_bytes(stream.read(start-6))
        stream.seek(0)
        content = temp / 'ota-signed-content'
        with content.open('wb') as output:
            left = signed_length
            while left:
                chunk = stream.read(min(left,4*1024*1024))
                assert chunk
                output.write(chunk)
                left -= len(chunk)
    run(['openssl','cms','-verify','-binary','-inform','DER','-in',str(signature),'-content',str(content),'-noverify','-out',os.devnull])
    certs = run(['openssl','pkcs7','-inform','DER','-in',str(signature),'-print_certs'])
    cert_der = run(['openssl','x509','-outform','DER'], input=certs)
    expected_der = run(['openssl','x509','-in',str(args.keys/'releasekey.x509.pem'),'-outform','DER'])
    assert cert_der == expected_der
    checks['ota_whole_file_signature_verified'] = True
    checks['ota_partition_references'] = sorted(partitions)
    checks['data_preserved_by_ota'] = True
    report = {'images':images, 'rom_zip':str(ota), 'rom_zip_sha256':sha(ota),'ota_metadata':metadata}
    (args.release/'native-image-check.json').write_text(json.dumps(report,indent=2)+'\n')
    checks['rom_zip_sha256'] = report['rom_zip_sha256']
    checks['passed'] = True
    (args.release/'release-signature-check.json').write_text(json.dumps(checks,indent=2)+'\n')
    print(json.dumps(checks,indent=2))
