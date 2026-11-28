#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage the LineageOS 21 2026-11-28 release (ABGR TWRP + helper identity), local commits only.

Fresh clones of the device, integration and download repositories at the heads
published on 2026-11-28 (release 20261127); the one device change, the TWRP
rewrite tools/report and release reports into the integration repository, and
8 public assets (new ROM, new TWRP image and AP tar). Nothing is pushed here;
publish-release-twrp21.py pushes, tags and creates the release.
"""
import hashlib, json, shutil, subprocess
from datetime import datetime, timezone
from pathlib import Path

J = Path('/srv/android/ports/lineage21-twrp-20261128')
A = Path('/srv/android/artifacts/lineage21-twrp-20261128')
L = Path('/srv/android/logs/lineage21-twrp-20261128')
R = Path('/srv/android/artifacts/lineage-21-arm64/release')
PORT = Path('/srv/android/ports/lineage-21-arm64/lineage-21')
PREV = Path('/srv/android/artifacts/lineage21-fixes-20261127')
DOCS = J / 'publication-docs'
W = J / 'publication'
D, I, N = W / 'device', W / 'integration', W / 'downloads'
TAG = 'lineage-21.0-arm64-20261128'
BUILD = 'gta3xlwifi.arm64.20261128.090043'
OTA = R / 'lineage-21.0-20261128-UNOFFICIAL-gta3xlwifi-arm64-privatekeys.zip'
PUBLIC_ROM = 'lineage-21.0-20261128-UNOFFICIAL-gta3xlwifi-arm64.zip'
ROM_SHA = '9bc87b1bf79663eb7dd88029494a9fc9b1a791cf3d0fb1c709a4fdd99e38d80d'
TWRP_IMG = A / 'twrp-3.7.1_12-gta3xlwifi-arm64-20261128.img'
TWRP_TAR = A / 'twrp-3.7.1_12-gta3xlwifi-arm64-20261128-ap.tar'
TWRP_SHA = '947d409b9ffb819ab9920f5e5d468ba156c236dfc3a645020c1825ad1f7c9649'
TAR_SHA = '99db5ccac26a70af22e9722ac052394a37035b4102785d41606c4a8bacc22882'
CPP = 'recovery-header-sync/recovery_header_sync.cpp'
HEADS = {'android_device_samsung_gta3xlwifi': ('lineage-21.0-arm64', '8d45348e8543eb6200aec97bf7325e9d2c88139e', D),
         'android_build_samsung_gta3xlwifi': ('lineage-21.0-arm64', '94a6403d7806e7d2001411a1ff9277a7e2bbc711', I),
         'lineageos21_gta3xlwifi': ('main', '57bdf2e2f9f319153090a0c4f116121bf364efe7', N)}
ME = ['-c', 'user.name=oddhap', '-c', 'user.email=1021373+oddhap@users.noreply.github.com']


def git(p, *a):
    return subprocess.check_output(['git', '-C', str(p), *a], text=True).strip()


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 23), b''):
            h.update(b)
    return h.hexdigest()


assert (L / 'twrp21-build.exit').read_text().strip() == '0'
assert json.loads((R / 'offline-validation.json').read_text())['passed']
assert json.loads((A / 'signed-fixes-check.json').read_text())['passed']
twrp_report = json.loads((A / 'twrp21-abgr-report.json').read_text())
assert twrp_report['passed'] and twrp_report['output_image_sha256'] == TWRP_SHA
assert sha(OTA) == ROM_SHA and sha(TWRP_IMG) == TWRP_SHA and sha(TWRP_TAR) == TAR_SHA
assert 'passed 14 cases' in (L / 'header-sync-test.log').read_text()
assert not W.exists()
W.mkdir()
for repo, (branch, head, path) in HEADS.items():
    subprocess.run(['git', 'clone', '-q', '--branch', branch, 'https://github.com/oddhap/%s.git' % repo, str(path)], check=True)
    assert git(path, 'rev-parse', 'HEAD') == head, repo

# Device: only the helper identity.
assert sha(D / CPP) == '563f59a2b1ed70e4a8b81db8ad2732958b493066678f12f329a29455ea41a157'
shutil.copy2(J / 'recovery_header_sync.cpp', D / CPP)
assert sha(D / CPP) == '007fbee32149c34a604a6327038487cdcdc2babe88da248eb663f3c220109eb4'
assert sha(D / CPP) == sha('/srv/android/src/lineage-21.0-arm64/device/samsung/gta3xlwifi/' + CPP)
git(D, 'add', CPP)
git(D, 'diff', '--cached', '--check')
assert git(D, 'diff', '--cached', '--name-only') == CPP
git(D, *ME, 'commit', '-q', '-m', '''gta3xlwifi: recognize the ABGR TWRP in the recovery header helper

The 2026-11-28 LineageOS 21 TWRP is the 15 October image with only
libminuitwrp rebuilt for ABGR_8888 (blue accent). Add its identity
(bytes 44..47 excluded, like the others) so OTAs keep its header in step
with the ROM. Existing identities are unchanged.''')
device_commit = git(D, 'rev-parse', 'HEAD')

# Integration: TWRP rewrite, tools, reports, lock, docs.
tw = I / 'lineage-21/twrp/abgr-20261128'
tw.mkdir(parents=True)
for n in ('prepare-twrp21-abgr.py', 'test-twrp21-header-sync.py'):
    shutil.copy2(J / n, tw / n)
shutil.copy2(A / 'twrp21-abgr-report.json', tw / 'report.json')
shutil.copy2(L / 'header-sync-test.log', tw / 'header-sync-test.log')
shutil.copy2(DOCS / 'twrp-README.md', tw / 'README.md')
t = I / 'lineage-21/tools'
for n in ('run-twrp21.sh', 'prepare-publication-twrp21.py', 'publish-release-twrp21.py'):
    shutil.copy2(J / n, t / n)
rep = I / 'reports/release-20261128'
rep.mkdir()
for f in sorted(R.glob('*.json')):
    shutil.copy2(f, rep / f.name)
shutil.copy2(A / 'signed-fixes-check.json', rep / 'signed-fixes-check.json')
shutil.copy2(A / 'twrp21-abgr-report.json', rep / 'twrp-abgr-report.json')
shutil.copy2(DOCS / 'release-notes.md', rep / 'release-notes.md')
prev = json.loads((I / 'reports/release-20261127/validation-summary.json').read_text())
summary = dict(prev)
summary.update({
    'checked_at_utc': datetime.now(timezone.utc).isoformat(),
    'file': PUBLIC_ROM,
    'bytes': OTA.stat().st_size,
    'build_incremental': BUILD,
    'rom_zip_sha256': ROM_SHA,
    'scope': '20261127 build plus the OTA recovery-header helper identity for the ABGR TWRP; TWRP with corrected colours',
    'offline_checks': json.loads((R / 'offline-validation.json').read_text())['checks'],
    'twrp_image': TWRP_IMG.name,
    'twrp_image_sha256': TWRP_SHA,
    'twrp_changed_files': twrp_report['changed_cpio_entries'],
    'twrp_ota_identity_sha256': twrp_report['ota_preflight_identity']['sha256_bytes44_47_zeroed'],
    'recovery_header_helper_host_cases_passed': 14,
    'twrp_physically_tested_on_lineage21': False,
})
(rep / 'validation-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
lockpath = I / 'lineage-21/notes/source-inputs.lock.json'
lock = json.loads(lockpath.read_text())
lock['android_device_samsung_gta3xlwifi'].update(commit=device_commit, publication_pending=False)
lock['inputs']['recommended_twrp_image_sha256'] = TWRP_SHA
lock['inputs']['twrp_abgr_rewrite'] = 'lineage-21/twrp/abgr-20261128/'
lock['validation'].update(report='../../reports/release-20261128/validation-summary.json',
                          build_incremental=BUILD, rom_zip_sha256=ROM_SHA)
lockpath.write_text(json.dumps(lock, indent=2) + '\n')
for n in ('README.md', 'BUILD_STATUS.md'):
    shutil.copy2(DOCS / ('int-README.md' if n == 'README.md' else n), I / n)

# Public assets: new ROM, new TWRP image and AP tar, unchanged rollback files.
P = A / 'public-assets'
P.mkdir()
for item in json.loads((PREV / 'asset-manifest.json').read_text()):
    n = item['name']
    if n in ('RESTORE_STOCK_VENDOR.sh', 'vbmeta-disabled.img', 'vendor-stock-T510XXU5CWA1.raw.img'):
        assert sha(PREV / 'public-assets' / n) == item['sha256'], n
        shutil.copy2(PREV / 'public-assets' / n, P / n)
shutil.copy2(OTA, P / PUBLIC_ROM)
shutil.copy2(TWRP_IMG, P / TWRP_IMG.name)
shutil.copy2(TWRP_TAR, P / TWRP_TAR.name)
shutil.copy2(DOCS / 'INSTALL.md', P / 'INSTALL.md')
(P / 'SHA256SUMS').write_text(''.join(sha(p) + '  ' + p.name + '\n' for p in sorted(P.iterdir())))
manifest = [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(P.iterdir())]
assert len(manifest) == 8, [m['name'] for m in manifest]
(A / 'asset-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
shutil.copy2(P / 'INSTALL.md', I / 'INSTALL_ARM64.md')
shutil.copy2(DOCS / 'release-notes.md', A / 'release-notes.md')

# Download repository.
shutil.copy2(DOCS / 'dl-README.md', N / 'README.md')
shutil.copy2(P / 'INSTALL.md', N / 'INSTALL.md')
shutil.copy2(rep / 'validation-summary.json', N / 'validation-summary.json')
for p in (I, N):
    git(p, 'add', '-A')
    git(p, 'diff', '--cached', '--check', '--', '.', ':!*.patch', ':!*.log')
    staged = git(p, 'diff', '--cached', '--name-only').splitlines()
    for s in staged:
        assert not s.endswith(('.pk8', '.pem', '.key', '.jks', '.keystore', '.zip', '.img', '.tar')), s
    if p == N:
        assert set(staged) == {'README.md', 'INSTALL.md', 'validation-summary.json'}, staged
    else:
        assert all(s in ('README.md', 'BUILD_STATUS.md', 'INSTALL_ARM64.md') or s.startswith(
            ('lineage-21/twrp/abgr-20261128/', 'lineage-21/tools/', 'lineage-21/notes/', 'reports/release-20261128/')) for s in staged), staged
    print(p.name, len(staged), 'files staged')
git(I, *ME, 'commit', '-q', '-m', 'Publish LineageOS 21 TWRP with corrected colours and matching OTA helper (2026-11-28)')
git(N, *ME, 'commit', '-q', '-m', 'LineageOS 21 ARM64 2026-11-28: TWRP with corrected colours')
stage = {'tag': TAG, 'device_commit': device_commit, 'integration_commit': git(I, 'rev-parse', 'HEAD'),
         'downloads_commit': git(N, 'rev-parse', 'HEAD'), 'assets': manifest}
(A / 'publication-stage.json').write_text(json.dumps(stage, indent=2) + '\n')
print(json.dumps(stage, indent=2))
