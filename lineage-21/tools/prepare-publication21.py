#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage the LineageOS 21 fixes release for publication (local commits only).

Fresh clones of the device, integration and download repositories at the
published heads; device changes from device-changes.tar (hash-checked), kernel
patch and tools into the integration repository, public assets (8). Nothing is
pushed here; publish-release21.py pushes, tags and creates the release.
"""
import hashlib, json, shutil, subprocess, tarfile
from datetime import datetime, timezone
from pathlib import Path

J = Path('/srv/android/ports/lineage21-fixes-20261127')
A = Path('/srv/android/artifacts/lineage21-fixes-20261127')
L = Path('/srv/android/logs/lineage21-fixes-20261127')
R = Path('/srv/android/artifacts/lineage-21-arm64/release')
PORT = Path('/srv/android/ports/lineage-21-arm64/lineage-21')
KREP = A / 'kernel-exfat21-20261127-01'
DOCS = J / 'publication-docs'
W = J / 'publication'
D, I, N = W / 'device', W / 'integration', W / 'downloads'
OLD = Path('/srv/android/artifacts/lineage21-bt-20261124')
TAG = 'lineage-21.0-arm64-20261127'
BUILD = 'gta3xlwifi.arm64.20261127.194723'
OTA = R / 'lineage-21.0-20261127-UNOFFICIAL-gta3xlwifi-arm64-privatekeys.zip'
PUBLIC_ROM = 'lineage-21.0-20261127-UNOFFICIAL-gta3xlwifi-arm64.zip'
ROM_SHA = 'cb902c61047cca3a23da924d7b0b63b0986e5200ed34be8357983dd79a1571c3'
HEADS = {'android_device_samsung_gta3xlwifi': ('lineage-21.0-arm64', '9432fe43b9156ba1c2ba5db017d77080275a945e', D),
         'android_build_samsung_gta3xlwifi': ('lineage-21.0-arm64', 'aa5ee2650138abcaaa2159e113544102ef1876ab', I),
         'lineageos21_gta3xlwifi': ('main', '176612b10a6b826f7e482f137ad8663e28bfbf84', N)}
ME = ['-c', 'user.name=oddhap', '-c', 'user.email=1021373+oddhap@users.noreply.github.com']


def git(p, *a):
    return subprocess.check_output(['git', '-C', str(p), *a], text=True).strip()


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 23), b''):
            h.update(b)
    return h.hexdigest()


assert (L / 'sign-fixes21-resume.exit').read_text().strip() == '0'
assert json.loads((R / 'offline-validation.json').read_text())['passed']
assert json.loads((A / 'signed-fixes-check.json').read_text())['passed']
assert json.loads((KREP / 'report.json').read_text())['passed']
assert sha(OTA) == ROM_SHA
assert not W.exists()
W.mkdir()
for repo, (branch, head, path) in HEADS.items():
    subprocess.run(['git', 'clone', '-q', '--branch', branch, 'https://github.com/oddhap/%s.git' % repo, str(path)], check=True)
    assert git(path, 'rev-parse', 'HEAD') == head, repo

# Device tree: the 8 changed files, hashes as built.
expected = {}
for line in (J / 'device-new.sha256').read_text().splitlines():
    h, name = line.split(None, 1)
    expected[name.lstrip('*').removeprefix('./')] = h
with tarfile.open(J / 'device-changes.tar') as t:
    names = [m.name.removeprefix('./') for m in t.getmembers() if m.isfile()]
    t.extractall(D)
assert len(names) == 8, names
for n in names:
    assert sha(D / n) == expected[n], n
git(D, 'add', *names)
git(D, 'diff', '--cached', '--check')
git(D, *ME, 'commit', '-q', '-m', '''gta3xlwifi: port Lineage 24 ART, power and SD fixes; add Updater OTA

- PRODUCT_ENABLE_UFFD_GC := false: the 4.4 kernel has no userfaultfd, so
  boot and system code must be compiled for the CC collector ART runs.
- Power HAL: retry failed boost writes after 1-60 s instead of disabling
  boost until reboot (RetryBackoff, host test).
- Adoptable storage: ro.crypto.volume.options aes-256-xts:aes-256-cts:v1
  and persist.sys.adoptable=force_on (kernel exfat alias in the build repo).
- LineageOS Updater: lineage.updater.uri on the lineageos21_gta3xlwifi ota
  branch, changelog link; the OTA stops TWRP crypto services and unmounts
  vendor before the unchanged vendor-unmounted guard.''')
device_commit = git(D, 'rev-parse', 'HEAD')

# Integration: kernel patch, tools, reports, lock, docs.
k = I / 'lineage-21/kernel/exfat'
k.mkdir(parents=True)
patch = Path('/srv/android/ports/lineage-24.0-arm64/kernel-sdfat-exfat24-20261123-01/sdfat-exfat-alias.patch')
assert sha(patch).startswith('e3ffcd8e')
shutil.copy2(patch, k / patch.name)
shutil.copy2(J / 'build-kernel-exfat21.sh', k / 'build-kernel-exfat21.sh')
src = '/srv/android/ports/lineage-24.0-arm64/lineage-24.0/tools/test-kernel-sdfat-exfat24.py'
shutil.copy2(src, k / 'test-kernel-sdfat-exfat24.py')
shutil.copy2(KREP / 'report.json', k / 'report.json')
readme = (DOCS / 'kernel-exfat-README.md').read_text().replace('`e3ffcd8e…` (see `report.json`)', '`%s`' % sha(patch))
(k / 'README.md').write_text(readme)
t = I / 'lineage-21/tools'
for n in ('check-fixes21.py', 'publish-ota-index21.py', 'run-fixes21.sh', 'sign-fixes21.sh', 'resume-sign21.sh',
          'prepare-publication21.py', 'publish-release21.py'):
    shutil.copy2(J / n, t / n)
rep = I / 'reports/release-20261127'
rep.mkdir()
for f in sorted(R.glob('*.json')):
    shutil.copy2(f, rep / f.name)
for n in ('unsigned-fixes-check.json', 'signed-fixes-check.json'):
    shutil.copy2(A / n, rep / n)
shutil.copy2(KREP / 'report.json', rep / 'kernel-exfat-report.json')
shutil.copy2(J / 'README.md', rep / 'README.md')
shutil.copy2(DOCS / 'release-notes.md', rep / 'release-notes.md')
old = json.loads((OLD / 'candidate/validation-summary.json').read_text())
summary = {
    'passed': True,
    'checked_at_utc': datetime.now(timezone.utc).isoformat(),
    'file': PUBLIC_ROM,
    'bytes': OTA.stat().st_size,
    'build_incremental': BUILD,
    'rom_zip_sha256': ROM_SHA,
    'architecture': 'ARM64 with ARM32 app compatibility',
    'scope': 'LineageOS 24 fixes ported (ART CC dexpreopt, power-boost retry, SD card exFAT/adoptable) and LineageOS Updater OTA',
    'offline_checks': json.loads((R / 'offline-validation.json').read_text())['checks'],
    'kernel_image_sha256': 'c7b4a44fcb4f31ea53d86fe000270d6a20d0f9d3e5a84ae9249c9d0acba19aca',
    'vendor_sparse_sha256': old['vendor_sparse_sha256'],
    'art_oat_odex_concurrent_copying_true': 171,
    'art_oat_odex_concurrent_copying_false': 0,
    'fixes_check_on_signed_package_passed': True,
    'vendor_runtime_policy_and_vintf_passed': True,
    'gapps_capacity_passed': True,
    'persistent_signing_keys_unchanged': True,
    'updater_uri': 'https://raw.githubusercontent.com/oddhap/lineageos21_gta3xlwifi/ota/{device}.json',
    'physically_tested_on_lineage21': False,
    'owner_device_remains_on_lineage24': True,
}
(rep / 'validation-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
lockpath = I / 'lineage-21/notes/source-inputs.lock.json'
lock = json.loads((PORT / 'notes/source-inputs.lock.json').read_text())
pub = json.loads(lockpath.read_text())
assert {k: v for k, v in lock['inputs'].items() if k not in ('kernel_sha256', 'kernel_exfat_alias_report')} == \
       {k: v for k, v in pub['inputs'].items() if k != 'kernel_sha256'}
pub['inputs']['kernel_sha256'] = lock['inputs']['kernel_sha256']
pub['inputs']['kernel_exfat_alias_patch'] = 'lineage-21/kernel/exfat/sdfat-exfat-alias.patch'
pub['android_device_samsung_gta3xlwifi'].update(commit=device_commit, publication_pending=False)
pub['validation'] = {'candidate_pending_runtime': True, 'full_hardware_validation_complete': False,
                     'physically_tested_on_lineage21': False,
                     'report': '../../reports/release-20261127/validation-summary.json',
                     'offline_checks_passed': True, 'build_incremental': BUILD, 'rom_zip_sha256': ROM_SHA}
lockpath.write_text(json.dumps(pub, indent=2) + '\n')
for n in ('README.md', 'BUILD_STATUS.md'):
    shutil.copy2(DOCS / ('int-README.md' if n == 'README.md' else n), I / n)

# Public assets: unchanged rollback/TWRP files from 24 November, new ROM and docs.
P = A / 'public-assets'
P.mkdir()
for item in json.loads((OLD / 'asset-manifest.json').read_text()):
    n = item['name']
    if n not in ('INSTALL.md', 'SHA256SUMS') and not n.endswith('.zip'):
        assert sha(OLD / 'public-assets' / n) == item['sha256'], n
        shutil.copy2(OLD / 'public-assets' / n, P / n)
shutil.copy2(OTA, P / PUBLIC_ROM)
shutil.copy2(DOCS / 'INSTALL.md', P / 'INSTALL.md')
(P / 'SHA256SUMS').write_text(''.join(sha(p) + '  ' + p.name + '\n' for p in sorted(P.iterdir())))
manifest = [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(P.iterdir())]
assert len(manifest) == 8
(A / 'asset-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
shutil.copy2(P / 'INSTALL.md', I / 'INSTALL_ARM64.md')
shutil.copy2(DOCS / 'release-notes.md', A / 'release-notes.md')

# Download repository.
shutil.copy2(DOCS / 'dl-README.md', N / 'README.md')
shutil.copy2(P / 'INSTALL.md', N / 'INSTALL.md')
shutil.copy2(rep / 'validation-summary.json', N / 'validation-summary.json')
for p in (I, N):
    git(p, 'add', '-A')
    # Kernel patch context keeps the kernel's own whitespace (byte-identical LOS24 patch).
    git(p, 'diff', '--cached', '--check', '--', '.', ':!*.patch')
    staged = git(p, 'diff', '--cached', '--name-only').splitlines()
    for s in staged:
        assert not s.endswith(('.pk8', '.pem', '.key', '.jks', '.keystore', '.zip', '.img')), s
    if p == N:
        assert set(staged) == {'README.md', 'INSTALL.md', 'validation-summary.json'}, staged
    else:
        assert all(s in ('README.md', 'BUILD_STATUS.md', 'INSTALL_ARM64.md') or s.startswith(
            ('lineage-21/kernel/exfat/', 'lineage-21/tools/', 'lineage-21/notes/', 'reports/release-20261127/')) for s in staged), staged
    print(p.name, len(staged), 'files staged')
git(I, *ME, 'commit', '-q', '-m', 'Publish LineageOS 21 fixes ported from LineageOS 24 and Updater OTA support')
git(N, *ME, 'commit', '-q', '-m', 'LineageOS 21 ARM64 2026-11-27: built-in updates, ART, boost and SD card fixes')
stage = {'tag': TAG, 'device_commit': device_commit, 'integration_commit': git(I, 'rev-parse', 'HEAD'),
         'downloads_commit': git(N, 'rev-parse', 'HEAD'), 'assets': manifest}
(A / 'publication-stage.json').write_text(json.dumps(stage, indent=2) + '\n')
print(json.dumps(stage, indent=2))
