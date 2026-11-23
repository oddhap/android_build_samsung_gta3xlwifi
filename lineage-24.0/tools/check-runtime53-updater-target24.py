#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the snapshot44+45(+46 vendor hash, +53 kernel digest) Updater/OTA changes to the actual target files.

Runtime53: releasetools.py additionally carries the snapshot53 kernel-guard digest edit
(sdfat-exfat kernel); the chain 44 -> 45 -> 46 -> 53 is walked exactly.

Runtime45: releasetools.py must equal snapshot44 + the reviewed snapshot45 edit
(TWRP vendor quiesce after the first preflight, before the vendor guard).

Checks: device.mk, releasetools.py and recovery_header_sync.cpp equal the
reviewed selection (edits.json); SYSTEM/build.prop carries exactly one
lineage.updater.uri equal to the selected HTTPS raw.githubusercontent.com URL;
the Updater priv-app, its init rc (/data/lineageos_updates) and permissions are
packaged; otacerts.zip holds exactly the certificate the OTA is signed with
(public AOSP test key for test builds); INSTALL/bin/backuptool.* equal the
LineageOS sources; and the packaged releasetools hooks, run on the real
archive, emit the reviewed order: recovery preflight, vendor-unmounted guard,
write protection of vendor/product, addon.d backup, release (fails if either
is mounted), vendor-unmounted guard again; and after the writes a guarded
restore followed by the final read-only recovery recheck. Packaging only."""
import hashlib, importlib.util, io, json, re, sys, types, zipfile
from pathlib import Path
top, archive, geometry, output = map(Path, sys.argv[1:5])
certificate = Path(sys.argv[5]) if len(sys.argv) > 5 else top/'build/make/target/product/security/testkey.x509.pem'
assert not output.exists()
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
def sha(f):
    h = hashlib.sha256()
    with f.open('rb') as s:
        for b in iter(lambda: s.read(1048576), b''): h.update(b)
    return h.hexdigest()
g = json.loads(geometry.read_text()); assert g['artifact_checks_passed'] and sha(archive) == g['archive_sha256']
work = A/'runtime44-source-selection-20261121-01'
sel = json.loads((work/'edits.json').read_text())
assert len(sel) == 3 and {Path(n).name for n in sel} == {'device.mk', 'releasetools.py', 'recovery_header_sync.cpp'}
sel45 = json.loads((A/'runtime45-source-selection-20261121-01/edits.json').read_text())
sel46 = json.loads((A/'runtime46-ota-selection-20261122-01/edits.json').read_text())  # vendor hash only
sel53 = json.loads((A/'runtime53-source-selection-20261123-01/edits.json').read_text())  # kernel digest + product props
assert len(sel45) == 1 and len(sel46) == 1 and list(sel46) == list(sel45)
assert len(sel53) == 2 and {Path(n).name for n in sel53} == {'releasetools.py', 'lineage_gta3xlwifi.mk'}
for name, rec in sel.items():
    for step in (sel45, sel46, sel53):
        if name in step:
            assert step[name]['before_sha256'] == rec['after_sha256'], name
            rec = dict(rec, after_sha256=step[name]['after_sha256'])
            sel[name] = rec
    assert sha(Path(name)) == rec['after_sha256'], name
quiesce = (A/'runtime45-source-selection-20261121-01/recovery-vendor-quiesce.sh').read_bytes()
plink = (A/'runtime45-source-selection-20261121-01/recovery-product-link.sh').read_bytes()
q45 = json.loads((A/'runtime45-source-selection-20261121-01/quiesce.json').read_text())
assert hashlib.sha256(quiesce).hexdigest() == q45['recovery_vendor_quiesce_sha256'] and hashlib.sha256(plink).hexdigest() == q45['recovery_product_link_sha256']
cfg = json.loads((work/'updater.json').read_text())
uri = cfg['lineage.updater.uri']
assert re.fullmatch(r'https://raw\.githubusercontent\.com/oddhap/android_build_samsung_gta3xlwifi/ota/\{device\}\.json', uri) and len(uri.encode()) <= 91
guard = (work/'addon-vendor-guard.sh').read_bytes()
assert hashlib.sha256(guard).hexdigest() == cfg['addon_vendor_guard_sha256']
dev = top/'device/samsung/gta3xlwifi'
sys.path.insert(0, str(top/'build/make/tools/releasetools')); sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('selected_releasetools', dev/'releasetools.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
guard = (A/'runtime45-source-selection-20261121-01/addon-vendor-guard.sh').read_bytes()  # snapshot45 replaced it
assert hashlib.sha256(guard).hexdigest() == q45['addon_vendor_guard_sha256']
assert m._ADDON_GUARD == guard and m._VENDOR_QUIESCE == quiesce and m._PRODUCT_LINK == plink


class Script:
    def __init__(self): self.lines = []
    def AppendExtra(self, line): self.lines.append(line)


with zipfile.ZipFile(archive) as z:
    assert z.read('META/releasetools.py') == (dev/'releasetools.py').read_bytes()
    props = z.read('SYSTEM/build.prop').decode()
    found = [l for l in props.splitlines() if l.startswith('lineage.updater.uri=')]
    assert found == ['lineage.updater.uri=' + uri], found
    # ro.lineage.* live in the product build.prop (product is folded into system/product).
    prod = dict(l.split('=', 1) for l in (props + '\n' + z.read('SYSTEM/product/etc/build.prop').decode()).splitlines()
                if '=' in l and not l.startswith('#'))
    assert prod['ro.lineage.releasetype'] == 'UNOFFICIAL' and prod['ro.lineage.build.version'] == '24.0'
    assert prod['ro.lineage.device'] == 'gta3xlwifi' and prod['ro.build.version.sdk'] == '37'
    names = set(z.namelist())
    for n in ['SYSTEM/system_ext/priv-app/Updater/Updater.apk', 'SYSTEM/system_ext/etc/permissions/Updater.xml',
              'SYSTEM/system_ext/etc/init/init.lineage-updater.rc', 'SYSTEM/bin/uncrypt', 'SYSTEM/etc/init/uncrypt.rc']:
        assert n in names, n
    assert b'/data/lineageos_updates' in z.read('SYSTEM/system_ext/etc/init/init.lineage-updater.rc')
    with zipfile.ZipFile(io.BytesIO(z.read('SYSTEM/etc/security/otacerts.zip'))) as certs:
        members = certs.namelist()
        assert len(members) == 1 and certs.read(members[0]) == certificate.read_bytes(), members
    for n in ['backuptool.sh', 'backuptool.functions']:
        assert z.read('INSTALL/bin/' + n) == (top/'vendor/lineage/prebuilt/common/bin'/n).read_bytes(), n
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as fixture:
        info = types.SimpleNamespace(input_zip=z, target_zip=None, output_zip=fixture, script=Script())
        m._begin(info); begin = list(info.script.lines)
        info.script.lines.clear(); m._end(info); end = list(info.script.lines)
    with zipfile.ZipFile(out) as fixture:
        assert fixture.read('addon-vendor-guard.sh') == guard
        assert fixture.read('recovery-vendor-quiesce.sh') == quiesce
        assert fixture.read('recovery-product-link.sh') == plink
        assert fixture.read('vendor-unmounted-check.sh') == m._VENDOR_MOUNT_GUARD
sysdev = '/dev/block/platform/13500000.dwmmc0/by-name/system'
def kind(line):
    if '"--preflight"' in line: return 'preflight'
    if line == 'run_program("/sbin/sh", "/tmp/recovery-vendor-quiesce.sh");': return 'quiesce'
    if line.startswith('assert(run_program("/sbin/sh", "/tmp/recovery-product-link.sh") == "0" ||'): return 'product-link-or-abort'
    if 'vendor-unmounted-check.sh") ==' in line: return 'vendor-guard'
    if 'addon-vendor-guard.sh", "protect") == "0" ||' in line: return 'protect-or-abort'
    if 'addon-vendor-guard.sh", "release") == "0" ||' in line: return 'release-or-abort'
    if line == 'run_program("/tmp/install/bin/backuptool.sh", "backup", "%s", "ext4");' % sysdev: return 'backup'
    if line == 'run_program("/tmp/install/bin/backuptool.sh", "restore", "%s", "ext4");' % sysdev: return 'restore'
    if line.startswith('if run_program("/sbin/sh", "/tmp/addon-vendor-guard.sh", "protect") == "0" then'): return 'if-protect'
    if line == 'run_program("/sbin/sh", "/tmp/addon-vendor-guard.sh", "release");': return 'release'
    if line.startswith('else ui_print(') and line.endswith('endif;'): return 'else-endif'
    return None
bk = [k for k in map(kind, begin) if k]
ek = [k for k in map(kind, end) if k]
assert bk == ['preflight', 'quiesce', 'product-link-or-abort', 'vendor-guard', 'protect-or-abort', 'backup', 'release-or-abort', 'vendor-guard'], bk
assert ek == ['if-protect', 'restore', 'release', 'else-endif', 'preflight'], ek
text = '\n'.join(begin + end)
assert 'block_image_update' not in text and 'write_raw_image' not in text and '--apply' not in text
assert text.count('abort(') == 7 and 'format(' not in text and 'delete' not in text
output.write_text(json.dumps(dict(passed=True, scope=__doc__, archive_sha256=g['archive_sha256'],
    lineage_updater_uri=uri, otacerts_certificate_sha256=sha(certificate),
    addon_vendor_guard_sha256=q45['addon_vendor_guard_sha256'], recovery_vendor_quiesce_sha256=hashlib.sha256(quiesce).hexdigest(), recovery_product_link_sha256=hashlib.sha256(plink).hexdigest(), begin_order=bk, end_order=ek,
    source_sha256={k: r['after_sha256'] for k, r in sel.items()}, release_signed=False,
    device_touched=False), indent=2)+'\n')
print('PASS packaged Updater URI, otacerts, backuptool, TWRP vendor quiesce, /product link and addon.d hook order')
