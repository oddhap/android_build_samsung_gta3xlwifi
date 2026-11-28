#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Add a published LineageOS 21 SM-T510 release to the built-in Updater's OTA index.

The release itself (ROM zip, INSTALL.md, SHA256SUMS ...) is created by the normal
LineageOS 21 release process in oddhap/lineageos21_gta3xlwifi. This tool:
  1. verifies the local signed OTA zip: whole-file signature, otacert = the
     LineageOS 21 release certificate (SHA-256 fingerprint), BLOCK metadata for
     gta3xlwifi / SDK 34, no wipe/downgrade, no key-like members;
  2. checks that the release tag has exactly that file as an asset (size and
     GitHub SHA-256 digest) and that the download URL serves that size;
  3. writes gta3xlwifi.json on the `ota` branch (created on first use) and reads
     it back. lineage.updater.uri points at its raw.githubusercontent.com URL.

LineageOS 21 Updater format (packages/apps/Updater Utils.parseJson, lineage-21.0):
  {"response": [{"datetime": <ro.build.date.utc>, "filename", "id", "romtype":
   "UNOFFICIAL", "size", "url", "version": "21.0"}]}
Updater offers an entry only if version == ro.lineage.build.version, romtype ==
ro.lineage.releasetype and datetime > ro.build.date.utc. Newest first.

Without --publish nothing is changed (dry run). No device operation; never
uploads keys, logs or target-files.
"""
import argparse, base64, hashlib, json, re, struct, subprocess, sys, tempfile, time, urllib.request, zipfile
from pathlib import Path

REPO = 'oddhap/lineageos21_gta3xlwifi'
BRANCH = 'ota'  # lineage.updater.uri must fit 91 bytes
DEVICE = 'gta3xlwifi'
INDEX = DEVICE + '.json'
RAW = 'https://raw.githubusercontent.com/%s/%s/%s' % (REPO, BRANCH, INDEX)
RELEASE_CERT_SHA256 = '1e593d1563b438ceab3e694601a098cada7e983dfcb5164b6bf4cdce3171b852'
NAME_RE = re.compile(r'lineage-21\.0-(20\d{6})-UNOFFICIAL-gta3xlwifi-arm64(-privatekeys)?\.zip')


def die(msg):
    sys.exit('ERROR: ' + msg)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def gh_api(path, method='GET', fields=None, allow_404=False):
    cmd = ['gh', 'api', '-X', method, path]
    data = None
    if fields is not None:
        cmd += ['--input', '-']
        data = json.dumps(fields)
    r = subprocess.run(cmd, input=data, text=True, capture_output=True)
    if r.returncode:
        if allow_404 and ('HTTP 404' in r.stderr or 'Not Found' in r.stdout):
            return None
        die('gh api %s %s failed: %s' % (method, path, r.stderr.strip() or r.stdout.strip()))
    return json.loads(r.stdout) if r.stdout.strip() else {}


def verify_ota(ota, tmp):
    with zipfile.ZipFile(ota) as z:
        for n in z.namelist():
            if n.endswith(('.pk8', '.p12', '.pfx', '.key', '.pem', '.jks', '.keystore')):
                die('key-like member in OTA: ' + n)
        meta = dict(l.split('=', 1) for l in z.read('META-INF/com/android/metadata').decode().splitlines() if '=' in l)
        otacert = z.read('META-INF/com/android/otacert')
    if meta.get('ota-type') != 'BLOCK' or meta.get('pre-device') != DEVICE or meta.get('post-sdk-level') != '34':
        die('unexpected OTA metadata %s' % meta)
    if meta.get('ota-wipe') == 'yes' or meta.get('ota-downgrade') == 'yes':
        die('wipe/downgrade packages are not published')
    if '/release-keys' not in meta.get('post-build', ''):
        die('not a release-keys build')
    (tmp/'cert.pem').write_bytes(otacert)
    der = subprocess.run(['openssl', 'x509', '-in', str(tmp/'cert.pem'), '-outform', 'DER'], check=True,
                         capture_output=True).stdout
    if hashlib.sha256(der).hexdigest() != RELEASE_CERT_SHA256:
        die('otacert is not the LineageOS 21 release certificate')
    length = ota.stat().st_size
    with ota.open('rb') as f:
        f.seek(-6, 2)
        start, marker, comment = struct.unpack('<HHH', f.read())
        if marker != 0xffff or not 6 < start <= comment:
            die('OTA has no whole-file signature footer')
        f.seek(length - start)
        (tmp/'sig.der').write_bytes(f.read(start - 6))
        f.seek(0)
        left = length - comment - 2
        with (tmp/'signed.bin').open('wb') as out:
            while left:
                b = f.read(min(1 << 20, left))
                out.write(b)
                left -= len(b)
    r = subprocess.run(['openssl', 'cms', '-verify', '-binary', '-inform', 'DER', '-in', str(tmp/'sig.der'),
                        '-content', str(tmp/'signed.bin'), '-certfile', str(tmp/'cert.pem'), '-nointern',
                        '-noverify', '-out', '/dev/null'], capture_output=True, text=True)
    (tmp/'signed.bin').unlink()
    if r.returncode:
        die('OTA signature does not verify: ' + r.stderr.strip())
    return meta


def load_index():
    meta = gh_api('repos/%s/contents/%s?ref=%s' % (REPO, INDEX, BRANCH), allow_404=True)
    if meta is None:
        return None, []
    data = json.loads(base64.b64decode(meta['content']))
    if not isinstance(data, dict) or not isinstance(data.get('response'), list):
        die('index is not {"response": [...]}')
    return meta['sha'], data['response']


def write_index(old_sha, entries, message):
    content = (json.dumps({'response': entries}, indent=2) + '\n').encode()
    if old_sha is None:
        readme = (b'# LineageOS 21 OTA index for SM-T510 (gta3xlwifi)\n\n'
                  b'`' + INDEX.encode() + b'` is read by the built-in LineageOS Updater through\n'
                  b'`lineage.updater.uri`. Packages are the ROM zips of the GitHub Releases.\n')
        blobs = []
        for path, data in [('README.md', readme), (INDEX, content)]:
            b = gh_api('repos/%s/git/blobs' % REPO, 'POST', {'content': base64.b64encode(data).decode(), 'encoding': 'base64'})
            blobs.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': b['sha']})
        tree = gh_api('repos/%s/git/trees' % REPO, 'POST', {'tree': blobs})
        commit = gh_api('repos/%s/git/commits' % REPO, 'POST', {'message': message, 'tree': tree['sha'], 'parents': []})
        gh_api('repos/%s/git/refs' % REPO, 'POST', {'ref': 'refs/heads/' + BRANCH, 'sha': commit['sha']})
    else:
        gh_api('repos/%s/contents/%s' % (REPO, INDEX), 'PUT', {'message': message, 'branch': BRANCH,
               'content': base64.b64encode(content).decode(), 'sha': old_sha})
    for _ in range(12):
        meta = gh_api('repos/%s/contents/%s?ref=%s' % (REPO, INDEX, BRANCH))
        if base64.b64decode(meta['content']) == content:
            break
        time.sleep(5)
    else:
        die('index read-back through the API does not match')
    try:
        with urllib.request.urlopen(urllib.request.Request(RAW, headers={'Cache-Control': 'no-cache'}), timeout=20) as r:
            print('raw URL', 'matches' if r.read() == content else 'still serves a cached copy (CDN ~5 min)')
    except OSError as e:
        print('raw URL not readable yet:', e)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--tag', required=True, help='published release tag, e.g. lineage-21.0-arm64-20261128')
    p.add_argument('--ota', type=Path, required=True, help='local signed OTA zip (the release ROM zip)')
    p.add_argument('--asset-name', help='release asset name (default: OTA name without -privatekeys)')
    p.add_argument('--keep', type=int, default=3)
    p.add_argument('--publish', action='store_true')
    a = p.parse_args()
    m = NAME_RE.fullmatch(a.ota.name)
    if not m:
        die('unexpected OTA file name ' + a.ota.name)
    asset_name = a.asset_name or a.ota.name.replace('-privatekeys.zip', '.zip')
    if not NAME_RE.fullmatch(asset_name) or NAME_RE.fullmatch(asset_name).group(2):
        die('unexpected asset name ' + asset_name)
    with tempfile.TemporaryDirectory() as tmp:
        meta = verify_ota(a.ota, Path(tmp))
    digest, size, stamp = sha256(a.ota), a.ota.stat().st_size, int(meta['post-timestamp'])
    print('verified %s  %d bytes  sha256 %s  post-timestamp %d' % (a.ota.name, size, digest, stamp))
    rel = gh_api('repos/%s/releases/tags/%s' % (REPO, a.tag))
    if rel.get('draft') or rel.get('prerelease'):
        die('release is a draft or pre-release')
    asset = [x for x in rel['assets'] if x['name'] == asset_name]
    if len(asset) != 1 or asset[0]['size'] != size or asset[0].get('digest') != 'sha256:' + digest:
        die('release asset %s does not match the verified OTA' % asset_name)
    url = asset[0]['browser_download_url']
    with urllib.request.urlopen(urllib.request.Request(url, method='HEAD'), timeout=60) as r:
        if int(r.headers.get('Content-Length', -1)) != size:
            die('download URL serves a different size')
    entry = {'datetime': stamp, 'filename': asset_name, 'id': digest, 'romtype': 'UNOFFICIAL',
             'size': size, 'url': url, 'version': '21.0'}
    old_sha, entries = load_index()
    entries = [e for e in entries if e['datetime'] != stamp]
    entries = sorted(entries + [entry], key=lambda e: -e['datetime'])[:max(1, a.keep)]
    print('index (%s):' % RAW)
    print(json.dumps({'response': entries}, indent=2))
    if not a.publish:
        print('dry run; add --publish')
        return
    write_index(old_sha, entries, 'OTA index: %s (%s)' % (asset_name, a.tag))
    print('PUBLISHED index entry for', a.tag)


if __name__ == '__main__':
    main()
