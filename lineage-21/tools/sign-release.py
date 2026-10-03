#!/usr/bin/env python3
"""Sign target files and a non-A/B OTA with persistent, private project keys.

Private material stays outside the source tree. Existing keys are never rotated.
Stock vendor and presigned third-party packages retain their original signatures.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('target_files', type=Path)
parser.add_argument('--top', type=Path, default=Path('/srv/android/src/lineage-21.0'))
parser.add_argument('--keys', type=Path, default=Path('/srv/android/signing/gta3xlwifi'))
parser.add_argument('--output', type=Path, default=Path('/srv/android/artifacts/lineage-21/release'))
args = parser.parse_args()
os.umask(0o077)
args.keys.mkdir(parents=True, exist_ok=True, mode=0o700)
args.output.mkdir(parents=True, exist_ok=True)
os.chdir(args.top)
env = os.environ.copy()
env['PATH'] = str(args.top / 'out/host/linux-x86/bin') + ':' + str(args.top / 'prebuilts/jdk/jdk17/linux-x86/bin') + ':' + env['PATH']
env['TMPDIR'] = str(args.output / 'tmp')
Path(env['TMPDIR']).mkdir(exist_ok=True)

def run(command, **kwargs):
    return subprocess.run(command, check=True, env=env, **kwargs)

def parse(line):
    return dict(re.findall(r'(\w+)="([^"]*)"', line))

with zipfile.ZipFile(args.target_files) as archive:
    apks = [parse(line) for line in archive.read('META/apkcerts.txt').decode().splitlines() if line]
    apexes = [parse(line) for line in archive.read('META/apexkeys.txt').decode().splitlines() if line]
    old_boot = archive.read('BOOTABLE_IMAGES/boot.img')
    properties = dict(line.split('=', 1) for line in archive.read('SYSTEM/build.prop').decode().splitlines()
                      if '=' in line and not line.startswith('#'))
    version = properties['ro.lineage.version']
    if not re.fullmatch(r'21\.0-[0-9]{8}-UNOFFICIAL-gta3xlwifi', version):
        raise SystemExit('Unexpected device/version in target files: ' + version)

cert_paths = {item['certificate'] for item in apks if item['certificate'] not in ('PRESIGNED', 'EXTERNAL')}
cert_paths |= {item['container_certificate'] for item in apexes if item['container_certificate'] != 'PRESIGNED' and item['partition'] != 'vendor'}
by_der = {}
mapping = []

def make_key(name, bits=2048):
    stem = args.keys / name
    pk8, cert, pem = [Path(str(stem) + suffix) for suffix in ('.pk8', '.x509.pem', '.pem')]
    if pk8.exists() != cert.exists():
        raise SystemExit('Incomplete key pair: ' + name)
    if not pk8.exists():
        run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', f'rsa_keygen_bits:{bits}', '-out', str(pem)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(pem), '-outform', 'DER', '-out', str(pk8)])
        run(['openssl', 'req', '-new', '-x509', '-sha256', '-key', str(pem), '-out', str(cert), '-days', '10000', '-subj', '/C=NO/O=SM-T510 Native Project/OU=LineageOS 21/CN=' + name])
    if not pem.exists():
        run(['openssl', 'pkcs8', '-nocrypt', '-inform', 'DER', '-in', str(pk8), '-out', str(pem)])
    for path in (pk8, cert, pem):
        path.chmod(0o600)
    return stem

for original in sorted(cert_paths, key=lambda p: (not p.endswith('/testkey.x509.pem'), p)):
    old_der = run(['openssl', 'x509', '-in', original, '-outform', 'DER'], stdout=subprocess.PIPE).stdout
    digest = hashlib.sha256(old_der).hexdigest()
    if digest not in by_der:
        name = 'releasekey' if original == 'build/make/target/product/security/testkey.x509.pem' else 'cert-' + digest[:16]
        by_der[digest] = make_key(name)
    new = by_der[digest]
    new_der = run(['openssl', 'x509', '-in', str(new) + '.x509.pem', '-outform', 'DER'], stdout=subprocess.PIPE).stdout
    if old_der == new_der:
        raise SystemExit('Signing key was not replaced')
    mapping.append({'old_path': original[:-9], 'new_path': str(new), 'old_cert': old_der.hex(), 'new_cert': new_der.hex(),
                    'old_sha256': digest, 'new_sha256': hashlib.sha256(new_der).hexdigest()})

certificate_map = {item['old_path'] + '.x509.pem': item['new_path'] for item in mapping}
key_map_file = args.keys / 'certificate-map.json'
if key_map_file.exists() and json.loads(key_map_file.read_text()) != mapping:
    raise SystemExit('Certificate map changed; review migration before proceeding')
key_map_file.write_text(json.dumps(mapping, indent=2) + '\n')
signed = args.output / 'signed-target-files.zip'
ota = args.output / ('lineage-' + version + '-privatekeys.zip')
command = ['sign_target_files_apks', '-o', '-p', str(args.top / 'out/host/linux-x86'), '--allow_gsi_debug_sepolicy', '--skip_apks_with_path_prefix=VENDOR/']
for item in mapping:
    command += ['-k', item['old_path'] + '=' + item['new_path']]
for item in apexes:
    if item['container_certificate'] == 'PRESIGNED' or item['partition'] == 'vendor':
        command += ['--extra_apks', item['name'] + '=', '--extra_apex_payload_key', item['name'] + '=']
    else:
        payload = make_key('payload-' + item['name'].removesuffix('.apex'), 4096)
        command += ['--extra_apks', item['name'] + '=' + certificate_map[item['container_certificate']],
                    '--extra_apex_payload_key', item['name'] + '=' + str(payload) + '.pem']
command += [str(args.target_files.resolve()), str(signed)]
print('Signing APKs and APEXes with persistent private keys', flush=True)
run(command)
with zipfile.ZipFile(signed) as archive:
    if archive.read('IMAGES/boot.img') != old_boot:
        raise SystemExit('Signing changed the tested Samsung boot image')
    # Vendor is not installed by this OTA; retain the tested stock partition.
print('Generating signed OTA', flush=True)
run(['ota_from_target_files', '-k', str(args.keys / 'releasekey'), '--block', '--backup=true',
     str(signed), str(ota)])
print('Signed OTA ready: ' + str(ota), flush=True)
