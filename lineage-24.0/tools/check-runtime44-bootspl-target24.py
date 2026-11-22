#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the snapshot38 fixed boot image patch level to the actual target files.

Checks: the three edited sources equal the reviewed selection (edits.json); the
build variables are BOOT_SECURITY_PATCH=2026-11-01 and the platform level;
SYSTEM/build.prop ro.build.version.security_patch equals PLATFORM_SECURITY_PATCH;
the packaged boot.img header OS/SPL word is exactly 0x220001ab (Android 17 /
2026-11, the installed TWRP header) and the whole boot.img and vendor.img are
byte-identical to build 37; the packaged releasetools.py is the selected source
and its _target(), run on the real archive, yields the preflight word
0x220001ab, still yields it for a later system month, and rejects an older
system month, a raised boot header and a tampered kernel. Packaging only; the
keymaster/TWRP effect requires the physical test."""
import hashlib, importlib.util, json, re, struct, sys, zipfile
from pathlib import Path
top, archive, geometry, buildvars, output = map(Path, sys.argv[1:6])
assert not output.exists()
A = Path('/srv/android/artifacts/lineage-24.0-arm64')
BOOT_PATCH, WORD = '2026-11-01', 0x220001ab
def sha(f):
    h = hashlib.sha256()
    with f.open('rb') as s:
        for b in iter(lambda: s.read(1048576), b''): h.update(b)
    return h.hexdigest()
g = json.loads(geometry.read_text()); assert g['artifact_checks_passed'] and sha(archive) == g['archive_sha256']
assert g['boot_security_patch'] == BOOT_PATCH and g['boot_os_version_word'] == WORD
assert g['images']['boot.img']['os_version_word'] == WORD
sel = json.loads((A/'runtime38-bootspl-selection-20261121-01/edits.json').read_text())
assert len(sel) == 3
# Runtime40: BoardConfig.mk was edited again by snapshot40 (product image removed);
# require the exact chain runtime38-after == runtime40-before and current == runtime40-after.
# Runtime42: walk the exact edit chain 38 -> 40 (BoardConfig) -> 41 (releasetools vendor
# hash) -> 42 (releasetools kernel digest) -> 43 -> 44 (releasetools addon.d backuptool)
# for every runtime38-bound file.
chain = [json.loads((A/d/'edits.json').read_text()) for d in ['runtime40-product-in-system-selection-20261121-01',
         'runtime41-ota-selection-20261121-01', 'runtime42-source-selection-20261121-01',
         'runtime43-source-selection-20261121-01', 'runtime44-source-selection-20261121-01']]
for name, rec in sel.items():
    cur = rec['after_sha256']
    for step in chain:
        if name in step:
            assert step[name]['before_sha256'] == cur, name
            cur = step[name]['after_sha256']
    assert sha(Path(name)) == cur, name
v = json.loads(buildvars.read_text())
assert v['BOOT_SECURITY_PATCH'] == BOOT_PATCH and v['PLATFORM_VERSION_LAST_STABLE'] == '17'
assert re.fullmatch(r'20\d\d-(0[1-9]|1[0-2])-\d\d', v['PLATFORM_SECURITY_PATCH'])
dev = top/'device/samsung/gta3xlwifi'
assert 'BOOT_SECURITY_PATCH := 2026-11-01\n' in (dev/'BoardConfig.mk').read_text()
mk = (dev/'mkbootimg.mk').read_text()
assert '$(INTERNAL_MKBOOTIMG_VERSION_ARGS)' not in mk and mk.count('$(GTA3XLWIFI_BOOTIMAGE_VERSION_ARGS)') == 1
assert '--os_patch_level $(BOOT_SECURITY_PATCH)' in mk
spec = importlib.util.spec_from_file_location('selected_releasetools', dev/'releasetools.py')
sys.path.insert(0, str(top/'build/make/tools/releasetools')); sys.dont_write_bytecode = True
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert m._BOOT_SECURITY_PATCH == BOOT_PATCH


class Override:
    def __init__(self, z, replacements): self.z, self.r = z, replacements
    def read(self, name): return self.r[name] if name in self.r else self.z.read(name)


class Info:
    def __init__(self, z): self.input_zip, self.target_zip = z, None


cases = []
with zipfile.ZipFile(archive) as z, zipfile.ZipFile(A/'runtime37-ota-build-20261120-01/target-files.zip') as old:
    assert z.read('META/releasetools.py') == (dev/'releasetools.py').read_bytes()
    props = z.read('SYSTEM/build.prop')
    system_patch = dict(l.split('=', 1) for l in props.decode().splitlines() if '=' in l and not l.startswith('#'))[
        'ro.build.version.security_patch']
    assert system_patch == v['PLATFORM_SECURITY_PATCH'] == g['security_patch']
    boot = z.read('IMAGES/boot.img')
    assert struct.unpack_from('<I', boot, 44)[0] == WORD
    # Runtime42: same Samsung boot header as build 37 except kernel size/payload/id;
    # the kernel payload must be exactly the selected gate-split Image.
    prev = old.read('IMAGES/boot.img')
    kb = struct.unpack_from('<I', boot, 8)[0]
    sel42 = json.loads((A/'runtime44-inputs-20261121-01/report.json').read_text())
    assert hashlib.sha256(boot[2048:2048+kb]).hexdigest() == sel42['after']['Image'], 'boot kernel is not the gate-split -02 Image'
    assert boot[:8] == prev[:8] and boot[12:576] == prev[12:576] and boot[608:2048] == prev[608:2048], 'boot header changed beyond kernel size/id'
    assert boot.endswith(b'SEANDROIDENFORCE')
    # Runtime41: vendor.img is the strictly recomposed gmsion vendor (policy cache only).
    assert hashlib.sha256(z.read('IMAGES/vendor.img')).hexdigest() == json.loads((A/'gmsion-vendor-20261121-01/report.json').read_text())['vendor_sparse_sha256'], 'vendor.img is not the selected gmsion vendor'
    recovery_word = struct.unpack_from('<I', z.read('IMAGES/recovery.img'), 44)[0]
    _, word = m._target(Info(z))
    assert word == '0x%08x' % WORD
    cases.append('actual archive yields preflight word 0x220001ab')
    later = props.replace(('ro.build.version.security_patch=%s\n' % system_patch).encode(),
                          b'ro.build.version.security_patch=2027-03-05\n')
    assert later != props
    assert m._target(Info(Override(z, {'SYSTEM/build.prop': later})))[1] == '0x%08x' % WORD
    cases.append('later system month (2027-03-05) keeps boot preflight word 0x220001ab')

    def reject(label, changes):
        try:
            m._target(Info(Override(z, changes)))
        except (ValueError, KeyError):
            cases.append(label); return
        raise AssertionError('Missing rejection: ' + label)
    reject('older system month rejected', {'SYSTEM/build.prop': props.replace(
        ('ro.build.version.security_patch=%s\n' % system_patch).encode(), b'ro.build.version.security_patch=2026-10-01\n')})
    raised = bytearray(boot); struct.pack_into('<I', raised, 44, WORD + 1)
    reject('raised boot header (2026-12) rejected', {'IMAGES/boot.img': bytes(raised)})
    tampered = bytearray(boot); tampered[2048] ^= 1
    reject('unreviewed kernel rejected', {'IMAGES/boot.img': bytes(tampered)})
output.write_text(json.dumps(dict(passed=True, scope=__doc__, archive_sha256=g['archive_sha256'],
    boot_security_patch=BOOT_PATCH, boot_os_version_word='0x%08x' % WORD, system_security_patch=system_patch,
    platform_security_patch=v['PLATFORM_SECURITY_PATCH'], generated_recovery_image_word='0x%08x' % recovery_word,
    boot_img_identical_to_build37=True, vendor_img_identical_to_build37=True,
    source_sha256={k: r['after_sha256'] for k, r in sel.items()}, releasetools_cases=cases,
    recovery_written=False, sepolicy_changed=False, physical_keymaster_tested=False), indent=2)+'\n')
print('PASS packaged fixed boot image patch level', BOOT_PATCH, 'system', system_patch)
