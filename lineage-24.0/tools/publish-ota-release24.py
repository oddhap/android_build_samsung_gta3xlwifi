#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish a checked SM-T510 LineageOS 24.0 OTA to GitHub for the built-in Updater.

One run, from a finished package (readiness-report.json + SHA256SUMS + OTA zip):
  1. optionally fetch the package directory from the build server (scp, SHA-checked);
  2. verify readiness (technical_package_checks_passed), SHA-256/size, OTA metadata
     (BLOCK, gta3xlwifi, SDK 37), the whole-file signature against an explicit public
     certificate, and that the zip contains no key material;
  3. create the GitHub Release (tag lineage-24.0-YYYYMMDD-<post-timestamp>) and upload
     ONLY the OTA zip and a .sha256 file; then verify the asset size and digest;
  4. add the entry to {device}.json on the updater branch (raw.githubusercontent.com is
     what lineage.updater.uri points at) and read it back.

The Updater JSON format (packages/apps/Updater README / NetworkUpdate.kt):
  [{"datetime": <ro.build.date.utc>, "type": "unofficial", "version": "24.0",
    "files": [{"filename", "sha256", "size", "url", "os_patch_level", "os_sdk_level"}]}]
os_sdk_level must be present: the Updater drops entries whose SDK level (default 0)
is lower than the running SDK. Entries are kept newest first.

Without --publish nothing is changed (dry run). Test-key packages are refused unless
--allow-test-keys is given; they are then published as GitHub pre-releases.
Never uploads logs, reports, target-files or keys. No device operation.
"""
import argparse, base64, datetime, hashlib, json, re, shutil, struct, subprocess, sys, tempfile, time, urllib.request, zipfile
from pathlib import Path

REPO = 'oddhap/android_build_samsung_gta3xlwifi'
BRANCH = 'ota'  # short: lineage.updater.uri must fit PROP_VALUE_MAX (91 bytes)
DEVICE = 'gta3xlwifi'
INDEX = DEVICE + '.json'
RAW = 'https://raw.githubusercontent.com/%s/%s/%s' % (REPO, BRANCH, INDEX)
ROOT = Path(__file__).resolve().parents[3]
SERVER = 'builder@192.168.0.124'
SSH_KEY = '/Users/oddi/Documents/Samsung-ARM64/.private/build_ed25519'
SERVER_ARTIFACTS = '/srv/android/artifacts/lineage-24.0-arm64'
NAME_RE = re.compile(r'lineage-24\.0-(20\d{6})-UNOFFICIAL-gta3xlwifi(-test)?\.zip')


def die(msg):
    sys.exit('ERROR: ' + msg)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw).stdout


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


def fetch(label, dest):
    if not re.fullmatch(r'runtime\d+-ota-build-\d{8}-\d\d|release-\d{8}-\d\d', label):
        die('unexpected server label ' + label)
    dest.mkdir(parents=True, exist_ok=True)
    ssh = ['-i', SSH_KEY, '-o', 'BatchMode=yes']
    listing = run(['ssh', *ssh, SERVER, 'cd %s/%s && ls' % (SERVER_ARTIFACTS, label)]).split()
    zips = [n for n in listing if NAME_RE.fullmatch(n)]
    if len(zips) != 1 or 'readiness-report.json' not in listing or 'SHA256SUMS' not in listing:
        die('server package directory incomplete: %s' % listing)
    for n in ['readiness-report.json', 'SHA256SUMS', zips[0]]:
        if not (dest/n).exists():
            print('fetching', n)
            subprocess.run(['scp', '-q', *ssh, '%s:%s/%s/%s' % (SERVER, SERVER_ARTIFACTS, label, n), str(dest/n)], check=True)
    return dest


def verify_signature(ota, certificate, tmp):
    """Whole-file signature exactly as the recovery verifier defines it (CMS over the signed range)."""
    length = ota.stat().st_size
    with ota.open('rb') as f:
        f.seek(-6, 2)
        signature_start, marker, comment = struct.unpack('<HHH', f.read())
        if marker != 0xffff or not 6 < signature_start <= comment:
            die('OTA has no whole-file signature footer')
        f.seek(length - comment - 22)
        if f.read(4) != b'PK\x05\x06':
            die('bad EOCD')
        f.seek(length - signature_start)
        der = f.read(signature_start - 6)
        (tmp/'sig.der').write_bytes(der)
        signed = length - comment - 2
        f.seek(0)
        with (tmp/'signed.bin').open('wb') as out:
            left = signed
            while left:
                b = f.read(min(1 << 20, left))
                out.write(b)
                left -= len(b)
    r = subprocess.run(['openssl', 'cms', '-verify', '-binary', '-inform', 'DER', '-in', str(tmp/'sig.der'),
                        '-content', str(tmp/'signed.bin'), '-certfile', str(certificate), '-nointern', '-noverify',
                        '-out', '/dev/null'], capture_output=True, text=True)
    (tmp/'signed.bin').unlink()
    if r.returncode:
        die('OTA signature does not verify with %s: %s' % (certificate, r.stderr.strip()))


def load_index():
    meta = gh_api('repos/%s/contents/%s?ref=%s' % (REPO, INDEX, BRANCH), allow_404=True)
    if meta is None:
        return None, []
    data = json.loads(base64.b64decode(meta['content']))
    if not isinstance(data, list):
        die('index is not a JSON list')
    return meta['sha'], data


def create_branch(index_bytes, message):
    readme = (b'# LineageOS 24.0 OTA index for SM-T510 (gta3xlwifi)\n\n'
              b'`' + INDEX.encode() + b'` is read by the built-in LineageOS Updater through\n'
              b'`lineage.updater.uri`. It is generated by\n'
              b'`integration/lineage-24.0/tools/publish-ota-release24.py` on the\n'
              b'`lineage-24.0-arm64` branch. Packages are GitHub Release assets.\n')
    blobs = []
    for path, content in [('README.md', readme), (INDEX, index_bytes)]:
        b = gh_api('repos/%s/git/blobs' % REPO, 'POST', {'content': base64.b64encode(content).decode(), 'encoding': 'base64'})
        blobs.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': b['sha']})
    tree = gh_api('repos/%s/git/trees' % REPO, 'POST', {'tree': blobs})
    commit = gh_api('repos/%s/git/commits' % REPO, 'POST', {'message': message, 'tree': tree['sha'], 'parents': []})
    gh_api('repos/%s/git/refs' % REPO, 'POST', {'ref': 'refs/heads/' + BRANCH, 'sha': commit['sha']})


def write_index(old_sha, entries, message):
    content = (json.dumps(entries, indent=2) + '\n').encode()
    if old_sha is None:
        create_branch(content, message)
    else:
        gh_api('repos/%s/contents/%s' % (REPO, INDEX), 'PUT', {'message': message, 'branch': BRANCH,
               'content': base64.b64encode(content).decode(), 'sha': old_sha})
    return content


def readback(content):
    for attempt in range(12):
        meta = gh_api('repos/%s/contents/%s?ref=%s' % (REPO, INDEX, BRANCH))
        if base64.b64decode(meta['content']) == content:
            break
        time.sleep(5)
    else:
        die('index read-back through the API does not match')
    try:
        with urllib.request.urlopen(urllib.request.Request(RAW, headers={'Cache-Control': 'no-cache'}), timeout=20) as r:
            raw = r.read()
        print('raw URL', 'matches' if raw == content else 'still serves a cached copy (CDN max-age ~5 min)')
    except OSError as e:
        print('raw URL not readable yet:', e)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--package-dir', type=Path, help='local directory with OTA zip, SHA256SUMS, readiness-report.json')
    src.add_argument('--from-server', metavar='LABEL', help='fetch e.g. runtime45-ota-build-20261122-01 into artifacts/ota-release-LABEL/')
    src.add_argument('--remove-tag', help='remove the index entry for this release tag (and with --delete-release the release)')
    src.add_argument('--init-index', action='store_true', help='create the updater branch with an empty index if missing')
    p.add_argument('--certificate', type=Path, help='public x509 certificate the OTA must be signed with (release key)')
    p.add_argument('--allow-test-keys', action='store_true', help='accept the public AOSP test key (owner-approved tests only)')
    p.add_argument('--keep', type=int, default=3, help='number of index entries to keep (default 3)')
    p.add_argument('--notes', default='', help='extra release notes (public)')
    p.add_argument('--delete-release', action='store_true')
    p.add_argument('--publish', action='store_true', help='actually create the release and update the index')
    a = p.parse_args()
    run(['gh', 'auth', 'status'])

    if a.init_index:
        old_sha, entries = load_index()
        if old_sha is not None:
            print('index already exists with %d entries' % len(entries))
        elif a.publish:
            readback(write_index(None, [], 'Create the LineageOS 24.0 OTA index'))
        else:
            print('dry run; add --publish')
        return

    if a.remove_tag:
        old_sha, entries = load_index()
        keep = [e for e in entries if ('/releases/download/%s/' % a.remove_tag) not in e['files'][0]['url']]
        print('index entries: %d -> %d' % (len(entries), len(keep)))
        if a.publish:
            if len(keep) != len(entries):
                readback(write_index(old_sha, keep, 'Remove %s from the OTA index' % a.remove_tag))
            if a.delete_release:
                run(['gh', 'release', 'delete', a.remove_tag, '-R', REPO, '--yes', '--cleanup-tag'])
        else:
            print('dry run; add --publish')
        return

    d = fetch(a.from_server, ROOT/'artifacts'/('ota-release-' + a.from_server)) if a.from_server else a.package_dir
    zips = [x for x in d.iterdir() if NAME_RE.fullmatch(x.name)]
    if len(zips) != 1:
        die('expected exactly one OTA zip in %s' % d)
    ota = zips[0]
    test_named = NAME_RE.fullmatch(ota.name).group(2) is not None
    readiness = json.loads((d/'readiness-report.json').read_text())
    if not readiness.get('technical_package_checks_passed'):
        die('readiness report does not pass')
    digest, size = sha256(ota), ota.stat().st_size
    sums = dict(reversed(line.split(None, 1)) for line in (d/'SHA256SUMS').read_text().splitlines() if line.strip())
    listed = {Path(k.strip().lstrip('*')).name: v for k, v in sums.items()}
    if listed.get(ota.name) != digest or readiness['ota_sha256'] != digest or readiness['ota_bytes'] != size \
            or readiness['ota_filename'] != ota.name:
        die('SHA-256/size/name mismatch between zip, SHA256SUMS and readiness report')
    with zipfile.ZipFile(ota) as z:
        for n in z.namelist():
            if n.endswith(('.pk8', '.p12', '.pfx', '.key', '.pem', '.jks', '.keystore')) or 'private' in n.lower():
                die('key-like member in OTA: ' + n)
        meta = dict(l.split('=', 1) for l in z.read('META-INF/com/android/metadata').decode().splitlines() if '=' in l)
        otacert = z.read('META-INF/com/android/otacert')
    if meta.get('ota-type') != 'BLOCK' or meta.get('pre-device') != DEVICE or meta.get('post-sdk-level') != '37':
        die('unexpected OTA metadata %s' % meta)
    if meta.get('ota-wipe') == 'yes' or meta.get('ota-downgrade') == 'yes':
        die('wipe/downgrade packages are not published')
    stamp = int(meta['post-timestamp'])
    if readiness.get('ota_post_timestamp') not in (None, stamp):
        die('readiness post-timestamp mismatch')
    date = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime('%Y%m%d')
    if NAME_RE.fullmatch(ota.name).group(1) != date:
        die('file name date differs from post-timestamp date %s' % date)
    testkey = ROOT/'integration/lineage-24.0/keys/aosp-testkey.x509.pem'
    is_test = 'test-keys' in meta.get('post-build', '')
    if a.certificate:
        cert = a.certificate
    elif a.allow_test_keys:
        cert = testkey
    else:
        die('give --certificate RELEASE.x509.pem (or --allow-test-keys for an owner-approved test)')
    if otacert != cert.read_bytes():
        die('META-INF/com/android/otacert is not %s' % cert)
    if cert.read_bytes() == testkey.read_bytes():
        is_test = True
    if is_test and not a.allow_test_keys:
        die('package is test-key signed or a test-keys build; refused without --allow-test-keys')
    if is_test != test_named:
        die('file name -test suffix does not match the signing')
    with tempfile.TemporaryDirectory() as tmp:
        verify_signature(ota, cert, Path(tmp))
    print('verified %s  %d bytes  sha256 %s  post-timestamp %d  patch %s' % (ota.name, size, digest, stamp,
          meta['post-security-patch-level']))

    tag = 'lineage-24.0-%s-%d' % (date, stamp)
    url = 'https://github.com/%s/releases/download/%s/%s' % (REPO, tag, ota.name)
    entry = {'datetime': stamp, 'type': 'unofficial', 'version': '24.0',
             'files': [{'filename': ota.name, 'os_patch_level': meta['post-security-patch-level'], 'os_sdk_level': 37,
                        'sha256': digest, 'size': size, 'url': url}]}
    old_sha, entries = load_index()
    entries = [e for e in entries if e['datetime'] != stamp]
    entries = sorted(entries + [entry], key=lambda e: -e['datetime'])[:max(1, a.keep)]
    print('release tag', tag, '(pre-release, test keys)' if is_test else '')
    print('index (%s):' % RAW)
    print(json.dumps(entries, indent=2))
    if not a.publish:
        print('dry run; add --publish')
        return

    title = 'LineageOS 24.0 — SM-T510 — %s%s' % (date, ' (TEST KEYS, not for general use)' if is_test else '')
    notes = ('Android 17 / LineageOS 24.0 for Samsung SM-T510 (gta3xlwifi), non-A/B block OTA.\n\n'
             '- Install from Settings → System → Updater, or sideload in TWRP.\n'
             '- Security patch level: %s; build date (UTC): %s.\n'
             '- SHA-256: `%s`\n'
             '- Requires the recognized TWRP (header Android 17 / 2026-11); the package checks it before writing.\n'
             % (meta['post-security-patch-level'], datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc)
                .strftime('%Y-%m-%d %H:%M'), digest))
    if is_test:
        notes += '- Signed with the public AOSP test key: owner-approved OTA test only.\n'
    if a.notes:
        notes += '\n' + a.notes + '\n'
    with tempfile.TemporaryDirectory() as tmp:
        side = Path(tmp)/(ota.name + '.sha256')
        side.write_text('%s  %s\n' % (digest, ota.name))
        cmd = ['gh', 'release', 'create', tag, str(ota), str(side), '-R', REPO, '--target', 'lineage-24.0-arm64',
               '--title', title, '--notes', notes]
        if is_test:
            cmd.append('--prerelease')
        else:
            cmd.append('--latest=false')
        subprocess.run(cmd, check=True)
    rel = gh_api('repos/%s/releases/tags/%s' % (REPO, tag))
    asset = next((x for x in rel['assets'] if x['name'] == ota.name), None)
    if asset is None or asset['size'] != size or (asset.get('digest') and asset['digest'] != 'sha256:' + digest):
        die('uploaded asset does not match (size/digest); index NOT updated')
    req = urllib.request.Request(url, method='HEAD')
    with urllib.request.urlopen(req, timeout=60) as r:
        if int(r.headers.get('Content-Length', -1)) != size:
            die('download URL serves a different size; index NOT updated')
    content = write_index(old_sha, entries, 'OTA index: %s (%s)' % (ota.name, tag))
    readback(content)
    print('PUBLISHED', tag)


if __name__ == '__main__':
    main()
