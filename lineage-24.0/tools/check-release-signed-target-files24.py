#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind a release-signed target-files package to the fully checked test-key package.

The signed archive must come from sign_target_files_apks on the exact checked
archive (readiness PASS) and differ only where release signing must change it:
- re-signed APK/APEX/CAPEX entries, each now signed with an owner certificate
  (container) and, for APEX, an owner AVB payload key;
- SYSTEM otacerts.zip holding exactly the release certificate (the unused
  recovery-ramdisk copy may add LineageOS's public extra recovery key);
- build property files whose lines differ only by test-keys -> release-keys
  (and ro.build.display.id losing " test-keys", plus one trailing newline);
- */mac_permissions.xml whose seinfo certificates map back exactly to the
  AOSP ones (same key name, testkey -> releasekey);
- META/ bookkeeping, and the rebuilt IMAGES/system.img, IMAGES/recovery.img and
  their maps.
IMAGES/boot.img and IMAGES/vendor.img must be byte-identical. The rebuilt
system.img file tree (debugfs, contents and inode/xattr metadata) may differ
from the checked one only at the changed SYSTEM/ entries. No APK, APEX or CAPEX
in the signed system tree may still be signed with a public AOSP development
certificate. On success a derived geometry report (the checked geometry with
the signed archive/system hashes) is written for the container/block checks.
Only public certificates are read; no private key is opened."""
import argparse, hashlib, io, json, re, shutil, subprocess, tempfile, zipfile
from pathlib import Path
p = argparse.ArgumentParser(description=__doc__)
for n in ['top', 'readiness', 'unsigned', 'signed', 'geometry', 'certs', 'output']:
    p.add_argument('--' + n, type=Path, required=True)
a = p.parse_args(); O = a.output.resolve(); assert not O.exists(); O.mkdir(parents=True)
def sha(f):
    h = hashlib.sha256()
    with f.open('rb') as s:
        for b in iter(lambda: s.read(1 << 20), b''): h.update(b)
    return h.hexdigest()
bin = a.top/'out/host/linux-x86/bin'
r = json.loads(a.readiness.read_text()); g = json.loads(a.geometry.read_text())
assert r['technical_package_checks_passed'] and r['target_files_sha256'] == sha(a.unsigned) == g['archive_sha256']
assert g['artifact_checks_passed']
def der_sha(pem):
    out = subprocess.run(['openssl', 'x509', '-in', str(pem), '-outform', 'DER'], capture_output=True, check=True).stdout
    return hashlib.sha256(out).hexdigest()
owner = {der_sha(f): f.name for f in sorted(a.certs.glob('*.x509.pem'))}
dev = {der_sha(f): f.name for f in sorted((a.top/'build/make/target/product/security').glob('*.x509.pem'))}
assert len(owner) == 47 and not set(owner) & set(dev)
release = (a.certs/'releasekey.x509.pem').read_bytes()
def der_hex(pem):
    return subprocess.run(['openssl', 'x509', '-in', str(pem), '-outform', 'DER'], capture_output=True, check=True).stdout.hex()
names = ['platform', 'shared', 'media', 'networkstack', 'sdk_sandbox', 'bluetooth', 'nfc']
dhex = {k: der_hex(a.top/'build/make/target/product/security'/(k + '.x509.pem')) for k in names + ['testkey']}
ohex = {k: der_hex(a.certs/(k + '.x509.pem')) for k in names + ['releasekey']}
owner_avb = {}
for f in sorted(a.certs.glob('*.avbpubkey')):
    owner_avb[hashlib.sha1(f.read_bytes()).hexdigest()] = f.name
assert len(owner_avb) == 39
PROP = re.compile(r'(^|/)(build\.prop|prop\.default|default\.prop)$')
# Recovery images carry the rewritten recovery-ramdisk otacerts; the installer never writes
# recovery (container check), TWRP stays the recovery.
ALLOWED_IMAGES = {'IMAGES/system.img', 'IMAGES/system.map', 'IMAGES/recovery.img', 'IMAGES/recovery.map',
                  'OTA/recovery-two-step.img'}
changed, report = {}, {'apk_apex_resigned': 0, 'props': [], 'meta': [], 'images': [], 'otacerts': []}
tmp = Path(tempfile.mkdtemp(dir=O))
def signer(path):
    out = subprocess.run([str(bin/'apksigner'), 'verify', '--print-certs', str(path)], capture_output=True, text=True)
    assert out.returncode == 0, (path.name, out.stderr[-400:])
    found = set(re.findall(r'(?:Signer #\d+|V\d(?:\.\d+)? Signer): certificate SHA-256 digest: ([0-9a-f]{64})|Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})', out.stdout))
    certs = {x or y for x, y in found}
    assert certs, ('no signer found', path.name)  # never pass an empty signer set
    return certs
def avb_key(apex):
    with zipfile.ZipFile(apex) as z:
        pay = tmp/'apex_payload.img'; pay.write_bytes(z.read('apex_payload.img'))
    out = subprocess.run([str(bin/'avbtool'), 'info_image', '--image', str(pay)], capture_output=True, text=True, check=True).stdout
    pay.unlink()
    return re.search(r'Public key \(sha1\):\s+([0-9a-f]{40})', out).group(1)
with zipfile.ZipFile(a.unsigned) as u, zipfile.ZipFile(a.signed) as s:
    un, sn = set(u.namelist()), set(s.namelist())
    assert un == sn, ('entry sets differ', sorted(un ^ sn)[:20])
    for name in sorted(sn):
        if name.endswith('/'): continue
        ib, sb = u.read(name), s.read(name)
        if name in ('IMAGES/boot.img', 'IMAGES/vendor.img'):
            assert ib == sb, name + ' changed by signing'; continue
        if ib == sb:
            if name.startswith(('SYSTEM/', 'ROOT/')) and name.endswith(('.apk', '.apex', '.capex')):
                f = tmp/'x'; f.write_bytes(sb)
                assert not signer(f) & set(dev), ('still signed with an AOSP development key', name); f.unlink()
            continue
        changed[name] = hashlib.sha256(sb).hexdigest()
        if name in ALLOWED_IMAGES:
            report['images'].append(name)
        elif name.startswith('META/'):
            report['meta'].append(name)
        elif name.endswith('/otacerts.zip'):
            with zipfile.ZipFile(io.BytesIO(sb)) as c:
                got = sorted(c.read(x) for x in c.namelist())
            if name == 'SYSTEM/etc/security/otacerts.zip':  # what the Updater verifies against
                assert got == [release], name
            else:  # unused AOSP recovery image (TWRP is the recovery): Lineage extra recovery key allowed
                assert name == 'RECOVERY/RAMDISK/system/etc/security/otacerts.zip', name
                assert got == sorted([release, (a.top/'vendor/lineage/build/target/product/security/lineage.x509.pem').read_bytes()]), name
            report['otacerts'].append(name)
        elif name.endswith('mac_permissions.xml') and name.startswith('SYSTEM/'):
            # seinfo signer certificates are rewritten dev -> owner (same key name;
            # testkey -> releasekey). Mapping back must give the checked file exactly.
            text = sb.decode()
            assert not any(dhex[k] in text for k in dhex), ('AOSP development certificate left', name)
            for k, h in ohex.items():
                text = text.replace(h, dhex['testkey' if k == 'releasekey' else k])
            assert text.encode() == ib, name
            report['meta'].append(name)
        elif PROP.search(name):
            ul, sl = ib.decode().splitlines(), sb.decode().splitlines()
            while sl and sl[-1] == '' and len(sl) > len(ul): sl.pop()  # sign_target_files appends a newline
            def same(x, y):  # test-keys -> release-keys; ro.build.display.id loses " test-keys" (AOSP)
                return x == y or y.replace('release-keys', 'test-keys') == x or (
                    y.startswith('ro.build.display.id=') and y + ' test-keys' == x)
            assert len(ul) == len(sl) and all(same(x, y) for x, y in zip(ul, sl)), name
            report['props'].append(name)
        elif name.startswith(('SYSTEM/', 'ROOT/')) and name.endswith(('.apk', '.apex', '.capex')):
            f = tmp/Path(name).name; f.write_bytes(sb)
            certs = signer(f)
            assert certs and certs <= set(owner), ('not signed with an owner certificate', name)
            if name.endswith('.apex'):
                assert avb_key(f) in owner_avb, ('APEX payload not signed with an owner AVB key', name)
            f.unlink(); report['apk_apex_resigned'] += 1
        else:
            raise AssertionError('unexpected change: ' + name)
    for part in ['system']:
        for label, z in [('unsigned', u), ('signed', s)]:
            sp = tmp/(label + '.sparse.img'); raw = tmp/(label + '.raw.img')
            with z.open('IMAGES/system.img') as f, sp.open('wb') as out: shutil.copyfileobj(f, out, 1 << 20)
            subprocess.run([str(bin/'simg2img'), str(sp), str(raw)], check=True); sp.unlink()
            subprocess.run(['python3', str(Path(__file__).with_name('audit-ext4-tree24.py')), '--image', str(raw), '--output', str(O/('system-' + label))], check=True)
            raw.unlink(); shutil.rmtree(O/('system-' + label)/'tree', ignore_errors=True)
    ue = json.loads((O/'system-unsigned/report.json').read_text())['entries']
    se = json.loads((O/'system-signed/report.json').read_text())['entries']
    assert set(ue) == set(se), sorted(set(ue) ^ set(se))[:20]
    allowed = {'/system/' + n[len('SYSTEM/'):] for n in changed if n.startswith('SYSTEM/')}
    allowed |= {'/' + n[len('ROOT/'):] for n in changed if n.startswith('ROOT/')}
    diff = sorted(k for k in ue if ue[k] != se[k])
    assert diff and set(diff) <= allowed, ('system image differs outside re-signed entries', sorted(set(diff) - allowed)[:20])
    signed_system = hashlib.sha256(s.read('IMAGES/system.img')).hexdigest()
shutil.rmtree(tmp)
assert report['apk_apex_resigned'] > 100 and len(report['otacerts']) == 2 and 'IMAGES/system.img' in report['images']
d = dict(g); d['images'] = json.loads(json.dumps(g['images']))
d['images']['system.img'] = dict(d['images']['system.img'], sha256=signed_system)
d.update(archive_sha256=sha(a.signed), release_signed=True, derived_from_geometry_sha256=sha(a.geometry),
         derived_by='check-release-signed-target-files24.py (boot/vendor identical; system differs only at re-signed entries)')
(O/'geometry-policy.json').write_text(json.dumps(d, indent=2)+'\n')
(O/'report.json').write_text(json.dumps(dict(passed=True, scope=__doc__, unsigned_sha256=sha(a.unsigned), signed_sha256=sha(a.signed),
    readiness_sha256=sha(a.readiness), owner_certificates=len(owner), owner_avb_keys=len(owner_avb), changed_entries=changed,
    system_tree_differences=diff, release_certificate_sha256=hashlib.sha256(release).hexdigest(), **report), indent=2)+'\n')
print('PASS release-signed target files: %d APK/APEX re-signed with owner keys, otacerts = release key, boot/vendor identical, system tree differs only at re-signed entries' % report['apk_apex_resigned'])
