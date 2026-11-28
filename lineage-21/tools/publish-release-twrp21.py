#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Push the staged LineageOS 21 TWRP-colour release sources, tag them and publish the release.

Run after prepare-publication-twrp21.py. Pushes only the lineage-21.0-arm64 branches
(device, integration) and main of the download repository, tags all three,
creates a draft release, uploads the 8 staged assets, checks size and GitHub
SHA-256 for each, then publishes it as latest and verifies the public URLs.
The Updater index is written afterwards by publish-ota-index21.py.
"""
import hashlib, json, subprocess, urllib.request
from pathlib import Path
from urllib.parse import quote

J = Path('/srv/android/ports/lineage21-twrp-20261128')
A = Path('/srv/android/artifacts/lineage21-twrp-20261128')
W = J / 'publication'
D, I, N = W / 'device', W / 'integration', W / 'downloads'
REPO = 'oddhap/lineageos21_gta3xlwifi'
stage = json.loads((A / 'publication-stage.json').read_text())
TAG = stage['tag']


def git(p, *a):
    return subprocess.check_output(['git', '-C', str(p), *a], text=True).strip()


def api(path, method='GET', data=None, *extra):
    cmd = ['gh', 'api', path, '--method', method]
    if data is not None:
        f = A / 'publish-request.json'
        f.write_text(json.dumps(data))
        cmd += ['--input', str(f)]
    return json.loads(subprocess.check_output(cmd + list(extra), text=True))


assert api('user')['login'] == 'oddhap'
for p, key in ((D, 'device_commit'), (I, 'integration_commit'), (N, 'downloads_commit')):
    assert git(p, 'rev-parse', 'HEAD') == stage[key]
    assert git(p, 'status', '--porcelain') == ''
# Nothing else may have moved since staging (fast-forward only, no force).
before = {}
for p, repo, branch in ((D, 'android_device_samsung_gta3xlwifi', 'lineage-21.0-arm64'),
                        (I, 'android_build_samsung_gta3xlwifi', 'lineage-21.0-arm64'),
                        (N, 'lineageos21_gta3xlwifi', 'main')):
    remote = api('repos/oddhap/%s/branches/%s' % (repo, branch))['commit']['sha']
    assert git(p, 'rev-parse', 'HEAD~1') == remote, repo
    assert api('repos/oddhap/%s/git/matching-refs/tags/%s' % (repo, TAG)) == [], repo
    before[repo] = remote
releases_before = api('repos/%s/releases' % REPO)
for p, branch in ((D, 'lineage-21.0-arm64'), (I, 'lineage-21.0-arm64'), (N, 'main')):
    git(p, 'tag', TAG)
    git(p, 'push', '--atomic', 'origin', 'HEAD:refs/heads/' + branch, 'refs/tags/' + TAG)
    print('Pushed', p.name, git(p, 'rev-parse', 'HEAD'), flush=True)
cfg = {'repository': REPO, 'tag': TAG, 'url': 'https://github.com/%s/releases/tag/%s' % (REPO, TAG),
       'source_commit': stage['integration_commit'], 'device_source_commit': stage['device_commit'],
       'release_repository_commit': stage['downloads_commit'], 'branches_before': before}
(A / 'release-config.json').write_text(json.dumps(cfg, indent=2) + '\n')
body = (A / 'release-notes.md').read_text() + (
    '\n[Build sources](https://github.com/oddhap/android_build_samsung_gta3xlwifi/tree/%s) · '
    '[Device sources](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/%s)\n'
    % (cfg['source_commit'], cfg['device_source_commit']))
r = api('repos/%s/releases' % REPO, 'POST', {'tag_name': TAG, 'target_commitish': cfg['release_repository_commit'],
        'name': 'LineageOS 21 — SM-T510 ARM64 — 2026-11-28', 'body': body, 'draft': True, 'prerelease': False})
(A / 'draft-release.json').write_text(json.dumps(r, indent=2) + '\n')
rid = r['id']
manifest = stage['assets']
for item in manifest:
    print('Uploading', item['name'], flush=True)
    url = 'https://uploads.github.com/repos/%s/releases/%d/assets?name=%s' % (REPO, rid, quote(item['name'], safe=''))
    a = api(url, 'POST', None, '--header', 'Content-Type: application/octet-stream',
            '--input', str(A / 'public-assets' / item['name']))
    assert a['name'] == item['name'] and a['size'] == item['bytes'] and a['state'] == 'uploaded', a
    if a.get('digest'):
        assert a['digest'] == 'sha256:' + item['sha256'], a
assets = api('repos/%s/releases/%d/assets' % (REPO, rid))
assert len(assets) == len(manifest) == 8
for item in manifest:
    a = next(x for x in assets if x['name'] == item['name'])
    assert a['size'] == item['bytes'] and a['digest'] == 'sha256:' + item['sha256'], item['name']
published = api('repos/%s/releases/%d' % (REPO, rid), 'PATCH', {'draft': False, 'make_latest': 'true'})
assert not published['draft'] and not published['prerelease']
(A / 'published-release.json').write_text(json.dumps(published, indent=2) + '\n')
print('PUBLISHED', published['html_url'], flush=True)

# Verify the public release.
r = api('repos/%s/releases/tags/%s' % (REPO, TAG))
assert api('repos/%s/releases/latest' % REPO)['id'] == r['id']
assert api('repos/%s/git/ref/tags/%s' % (REPO, TAG))['object']['sha'] == cfg['release_repository_commit']
for item in manifest:
    a = next(x for x in r['assets'] if x['name'] == item['name'])
    assert a['state'] == 'uploaded' and a['size'] == item['bytes'] and a['digest'] == 'sha256:' + item['sha256']
    code = subprocess.check_output(['curl', '--fail', '--silent', '--show-error', '--location', '--head', '--output',
                                    '/dev/null', '--write-out', '%{http_code}', a['browser_download_url']], text=True)
    assert code == '200', (item['name'], code)
    if item['name'] == 'SHA256SUMS':
        assert hashlib.sha256(urllib.request.urlopen(a['browser_download_url']).read()).hexdigest() == item['sha256']
old = {x['id']: (x['tag_name'], x['name'], x['body'], len(x['assets'])) for x in releases_before}
now = {x['id']: (x['tag_name'], x['name'], x['body'], len(x['assets'])) for x in api('repos/%s/releases' % REPO)}
assert all(now[i] == v for i, v in old.items()), 'earlier releases changed'
receipt = {'passed': True, 'url': r['html_url'], 'release_id': r['id'], 'tag': TAG, 'public_assets': manifest,
           'all_public_asset_urls_ok': True, 'all_github_asset_sizes_and_sha256_match': True,
           'earlier_releases_unchanged': True, **{k: cfg[k] for k in ('source_commit', 'device_source_commit',
           'release_repository_commit')}, 'physically_tested_on_lineage21': False}
(A / 'publication-verification.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
