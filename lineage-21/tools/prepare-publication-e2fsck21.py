#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage the second LineageOS 21 2026-11-28 release (e2fsck FBE policy fix, issue #6), local commits only.

Fresh clones of the integration and download repositories at the heads published
with release lineage-21.0-arm64-20261128. The device tree is unchanged. Adds the
e2fsprogs patch (pinned in source-lock.json), build/sign/publication tools, the
issue #6 report and release reports to the integration repository, and stages 8
public assets (new ROM and INSTALL.md; TWRP and rollback files unchanged from the
previous release). Nothing is pushed here; publish-release-e2fsck21.py pushes,
tags and creates the release.
"""
import hashlib, json, shutil, subprocess
from datetime import datetime, timezone
from pathlib import Path

J = Path('/srv/android/ports/los21-issue6-20261128')
A = Path('/srv/android/artifacts/los21-issue6-20261128')
L = Path('/srv/android/logs/los21-issue6-20261128')
R = Path('/srv/android/artifacts/lineage-21-arm64/release')
PORT = Path('/srv/android/ports/lineage-21-arm64/lineage-21')
TOP = Path('/srv/android/src/lineage-21.0-arm64')
PREV = Path('/srv/android/artifacts/lineage21-twrp-20261128')
DOCS = J / 'publication-docs'
W = J / 'publication'
I, N = W / 'integration', W / 'downloads'
TAG = 'lineage-21.0-arm64-20261128-2'
BUILD = 'gta3xlwifi.arm64.20261128.104453'
E2FSPROGS_REV = 'd37e9f0ddce5c220aed237c0d97d732c773861cc'
PATCH_SHA = 'f6d36fc92402c546ed019d61c3669b5917809059f427f8ac59e427721456720c'
E2FSCK_SHA = 'ad0821dd331c8f1c41bb53db912ea6d0840bf83334d0d617b7cf7e0675e48f4e'
HEADS = {'android_build_samsung_gta3xlwifi': ('lineage-21.0-arm64', '887de62e1563dae2720e9dab5d121e8a30866687', I),
         'lineageos21_gta3xlwifi': ('main', 'c352989319cc876fb87e6b6ecaad271b06432682', N)}
ME = ['-c', 'user.name=oddhap', '-c', 'user.email=1021373+oddhap@users.noreply.github.com']


def git(p, *a):
    return subprocess.check_output(['git', '-C', str(p), *a], text=True).strip()


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 23), b''):
            h.update(b)
    return h.hexdigest()


assert (L / 'e2fsck21-build.exit').read_text().strip() == '0'
assert (L / 'e2fsck21-sign.exit').read_text().strip() == '0'
assert json.loads((R / 'offline-validation.json').read_text())['passed']
assert json.loads((A / 'signed-fixes-check.json').read_text())['passed']
otas = sorted(R.glob('lineage-21.0-*-UNOFFICIAL-gta3xlwifi-arm64-privatekeys.zip'))
assert len(otas) == 1
OTA = otas[0]
PUBLIC_ROM = OTA.name.replace('-privatekeys.zip', '.zip')
ROM_SHA = sha(OTA)
signed = (A / 'SIGNED-SHA256SUMS').read_text()
assert ROM_SHA + '  ' + OTA.name in signed
assert subprocess.check_output(['unzip', '-p', str(R / 'signed-target-files.zip'), 'SYSTEM/bin/e2fsck']) \
    and hashlib.sha256(subprocess.check_output(['unzip', '-p', str(R / 'signed-target-files.zip'),
                                                'SYSTEM/bin/e2fsck'])).hexdigest() == E2FSCK_SHA
patch = PORT / 'patches/external_e2fsprogs.patch'
assert sha(patch) == PATCH_SHA
e2fs = TOP / 'external/e2fsprogs'
assert git(e2fs, 'rev-parse', 'HEAD') == E2FSPROGS_REV
assert git(e2fs, 'diff') + '\n' == patch.read_text()
assert not W.exists()
W.mkdir()
for repo, (branch, head, path) in HEADS.items():
    subprocess.run(['git', 'clone', '-q', '--branch', branch, 'https://github.com/oddhap/%s.git' % repo, str(path)], check=True)
    assert git(path, 'rev-parse', 'HEAD') == head, repo

# Integration: e2fsprogs patch pinned like the other platform patches.
shutil.copy2(patch, I / 'lineage-21/patches/external_e2fsprogs.patch')
lockp = I / 'lineage-21/notes/source-lock.json'
records = json.loads(lockp.read_text())
assert not any(r['project'] == 'external/e2fsprogs' for r in records)
manifest_xml = (I / 'lineage-21/notes/pinned-build-manifest.xml').read_text()
assert 'path="external/e2fsprogs" revision="%s"' % E2FSPROGS_REV in manifest_xml
records.append({'project': 'external/e2fsprogs', 'revision': E2FSPROGS_REV, 'patch': 'external_e2fsprogs.patch',
                'sha256': PATCH_SHA, 'new_files': [], 'clean_index_patch_check_passed': True})
lockp.write_text(json.dumps(records, indent=2) + '\n')
npatches = len(records)
t = I / 'lineage-21/tools'
for n in ('run-e2fsck21.sh', 'sign-e2fsck21.sh', 'prepare-publication-e2fsck21.py', 'publish-release-e2fsck21.py'):
    shutil.copy2(J / n, t / n)
issue = I / 'reports/issue6-e2fsck-20261128'
shutil.copytree(DOCS / 'issue6-report', issue)
rep = I / 'reports/release-20261128-2'
rep.mkdir()
for f in sorted(R.glob('*.json')):
    shutil.copy2(f, rep / f.name)
shutil.copy2(A / 'signed-fixes-check.json', rep / 'signed-fixes-check.json')
shutil.copy2(DOCS / 'release-notes.md', rep / 'release-notes.md')
prev = json.loads((I / 'reports/release-20261128/validation-summary.json').read_text())
summary = dict(prev)
for k in ('twrp_changed_files',):
    summary.pop(k, None)
summary.update({
    'checked_at_utc': datetime.now(timezone.utc).isoformat(),
    'file': PUBLIC_ROM,
    'bytes': OTA.stat().st_size,
    'build_incremental': BUILD,
    'rom_zip_sha256': ROM_SHA,
    'scope': 'first 20261128 build plus the e2fsck fix for Samsung FBE contexts (issue #6); TWRP unchanged',
    'offline_checks': json.loads((R / 'offline-validation.json').read_text())['checks'],
    'e2fsck_sha256': E2FSCK_SHA,
    'e2fsprogs_patch_sha256': PATCH_SHA,
    'issue6_report': '../issue6-e2fsck-20261128/README.md',
    'physically_tested_on_lineage21': {
        'build': BUILD + ' (same build, local test-key signature)',
        'clean_install_with_mindthegapps': True,
        'magisk_31_1_unclean_reboot_boot_fsck_repaired_nothing': True,
        'lost_and_found_empty_user0_keys_present': True,
        'addon_d_update_preservation': False,
        'updater_ota_install': False,
    },
})
(rep / 'validation-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
lockpath = I / 'lineage-21/notes/source-inputs.lock.json'
lock = json.loads(lockpath.read_text())
lock['validation'].update(report='../../reports/release-20261128-2/validation-summary.json',
                          build_incremental=BUILD, rom_zip_sha256=ROM_SHA)
lockpath.write_text(json.dumps(lock, indent=2) + '\n')
readme = (DOCS / 'int-README.md').read_text()
old = 'All %d pinned port patches' % (npatches - 1)
assert readme.count(old) == 1, old
(I / 'README.md').write_text(readme.replace(old, 'All %d pinned port patches' % npatches))
shutil.copy2(DOCS / 'BUILD_STATUS.md', I / 'BUILD_STATUS.md')

# Public assets: new ROM and INSTALL.md, unchanged TWRP and rollback files.
P = A / 'public-assets'
P.mkdir()
for item in json.loads((PREV / 'asset-manifest.json').read_text()):
    n = item['name']
    if n in ('RESTORE_STOCK_VENDOR.sh', 'vbmeta-disabled.img', 'vendor-stock-T510XXU5CWA1.raw.img',
             'twrp-3.7.1_12-gta3xlwifi-arm64-20261128.img', 'twrp-3.7.1_12-gta3xlwifi-arm64-20261128-ap.tar'):
        assert sha(PREV / 'public-assets' / n) == item['sha256'], n
        shutil.copy2(PREV / 'public-assets' / n, P / n)
shutil.copy2(OTA, P / PUBLIC_ROM)
shutil.copy2(DOCS / 'INSTALL.md', P / 'INSTALL.md')
(P / 'SHA256SUMS').write_text(''.join(sha(p) + '  ' + p.name + '\n' for p in sorted(P.iterdir())))
manifest = [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(P.iterdir())]
assert len(manifest) == 8, [m['name'] for m in manifest]
assert next(m for m in manifest if m['name'] == PUBLIC_ROM)['sha256'] == ROM_SHA
(A / 'asset-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
shutil.copy2(P / 'INSTALL.md', I / 'INSTALL_ARM64.md')
shutil.copy2(DOCS / 'release-notes.md', A / 'release-notes.md')

# Download repository.
shutil.copy2(DOCS / 'dl-README.md', N / 'README.md')
shutil.copy2(P / 'INSTALL.md', N / 'INSTALL.md')
shutil.copy2(rep / 'validation-summary.json', N / 'validation-summary.json')
for p in (I, N):
    git(p, 'add', '-A')
    git(p, 'diff', '--cached', '--check', '--', '.', ':!*.patch', ':!*.log', ':!*.txt')
    staged = git(p, 'diff', '--cached', '--name-only').splitlines()
    for s in staged:
        assert not s.endswith(('.pk8', '.pem', '.key', '.jks', '.keystore', '.zip', '.img', '.tar')), s
        assert 'HANDOFF' not in s and '/._' not in '/' + s, s
    if p == N:
        assert set(staged) == {'README.md', 'INSTALL.md', 'validation-summary.json'}, staged
    else:
        assert all(s in ('README.md', 'BUILD_STATUS.md', 'INSTALL_ARM64.md', 'lineage-21/patches/external_e2fsprogs.patch',
                         'lineage-21/notes/source-lock.json', 'lineage-21/notes/source-inputs.lock.json')
                   or s.startswith(('lineage-21/tools/', 'reports/issue6-e2fsck-20261128/', 'reports/release-20261128-2/'))
                   for s in staged), staged
    print(p.name, len(staged), 'files staged')
git(I, *ME, 'commit', '-q', '-m', '''Fix boot-time e2fsck clearing Samsung FBE files on LineageOS 21 (#6)

The Samsung kernel sets EXT4_POLICY_FLAGS_PRIVATE_ALGO (0x04) in the
encryption context of files but not directories. e2fsprogs 1.46 compared
the full flags byte, so after an unclean shutdown the forced e2fsck -y
moved every encrypted file to lost+found (init_user0_failed). Ignore the
bit for v1 policies with different modes, as the kernel does; pin the
patch, add build/sign/publication tools, the investigation and the
reports of the 2026-11-28 (2) release.''')
git(N, *ME, 'commit', '-q', '-m', 'LineageOS 21 ARM64 2026-11-28 (2): e2fsck fix for data loss after unclean shutdown')
stage = {'tag': TAG, 'device_commit': subprocess.check_output(
             ['git', 'ls-remote', 'https://github.com/oddhap/android_device_samsung_gta3xlwifi.git',
              'refs/heads/lineage-21.0-arm64'], text=True).split()[0],
         'integration_commit': git(I, 'rev-parse', 'HEAD'),
         'downloads_commit': git(N, 'rev-parse', 'HEAD'), 'public_rom': PUBLIC_ROM, 'rom_sha256': ROM_SHA,
         'pinned_patches': npatches, 'assets': manifest}
(A / 'publication-stage.json').write_text(json.dumps(stage, indent=2) + '\n')
print(json.dumps(stage, indent=2))
