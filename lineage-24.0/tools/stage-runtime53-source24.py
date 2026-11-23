#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot53: SD-card storage (issue oddhap/android_build_samsung_gta3xlwifi#4).

- lineage_gta3xlwifi.mk: ro.crypto.volume.options=aes-256-xts:aes-256-cts:v1.
  Adoptable volumes are formatted F2FS; on this 4.4 kernel F2FS uses the generic
  fscrypt code, whose fscrypt_valid_enc_modes accepts only AES-256-XTS/AES-256-CTS
  (and 128-CBC/CTS, Speck). vold's default for ro.product.first_api_level <= 29 is
  AES-256-HEH filenames (FsCrypt.cpp), which F2FS rejects with EINVAL: "Failed to set
  encryption policy ... v1 modes 1/126 flags 0x2: Invalid argument" (as in issue 4).
  Same v1 policy version vold already uses here, kernel-accepted modes 1/4.
- lineage_gta3xlwifi.mk: persist.sys.adoptable=force_on (owner choice 2026-11-23).
  The SD slot line is in the pinned Samsung vendor fstab without encryptable=userdata,
  so vold reports no adoptable disk; StorageManagerService's force_on adds
  FLAG_ADOPTABLE instead. Vendor image stays byte-identical. Also applies to USB disks.
- releasetools.py: OTA kernel guard digest moves to the sdfat-exfat kernel (sdfat
  also registers as "exfat" so vold's Exfat::IsSupported accepts exFAT cards).
No SELinux, vendor, dtbo or other change."""
import hashlib, json, subprocess
from pathlib import Path
src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261123-52', port/'snapshots/port-20261123-53'
work = art/'runtime53-source-selection-20261123-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert json.loads((work/'source-before.json').read_text())['passed']
assert not after.exists()
k = json.loads((art/'kernel-sdfat-exfat-build-20261123-01/report.json').read_text())
sel = json.loads((art/'runtime53-inputs-20261123-01/report.json').read_text())
old, new = k['previous_Image_sha256'], k['Image_sha256']
assert k['passed'] and sel['after']['Image'] == new and old != new
assert sha(src/'device/samsung/gta3xlwifi/prebuilt/Image') == new
dev = src/'device/samsung/gta3xlwifi'
BEFORE = {dev/'releasetools.py': '049f78456d829872caad29e39f9c39fa1248facb47602b2c302c1990bcaed0af',
          dev/'lineage_gta3xlwifi.mk': 'e003b59a283efc934465396c60f49d005f2efb06c037b922fe319d3726437ece'}
PROPS = ('PRODUCT_EXTRA_VNDK_VERSIONS := 30\n',
         'PRODUCT_EXTRA_VNDK_VERSIONS := 30\n'
         '\n'
         '# SD-card storage (issue 4). Adoptable volumes are F2FS, and F2FS on this 4.4\n'
         '# kernel uses the generic fscrypt code, which accepts only AES-256-XTS with\n'
         '# AES-256-CTS filenames; vold\'s pre-Q default (AES-256-HEH filenames) is\n'
         '# rejected with EINVAL. The SD slot line is in the pinned Samsung vendor fstab\n'
         '# without encryptable=userdata, so offer adoptable storage through the\n'
         '# framework override (also applies to USB disks).\n'
         'PRODUCT_SYSTEM_PROPERTIES += \\\n'
         '    ro.crypto.volume.options=aes-256-xts:aes-256-cts:v1 \\\n'
         '    persist.sys.adoptable=force_on\n')
edits = {}
def edit(path, pairs):
    o = path.read_text(); u = o
    assert hashlib.sha256(o.encode()).hexdigest() == BEFORE[path], path
    for a, b in pairs:
        assert u.count(a) == 1, (path, a)
        u = u.replace(a, b)
    edits[path] = (o, u)
edit(dev/'releasetools.py', [(old, new)])
compile(edits[dev/'releasetools.py'][1], 'releasetools.py', 'exec')
edit(dev/'lineage_gta3xlwifi.mk', [PROPS])
assert 'ro.crypto.volume' not in edits[dev/'lineage_gta3xlwifi.mk'][0]
originals = work/'originals'
originals.mkdir()
for path, (o, u) in edits.items():
    (originals/(path.name + '.original')).write_text(o)
meta = {str(p): {'before_sha256': hashlib.sha256(o.encode()).hexdigest(),
                 'after_sha256': hashlib.sha256(u.encode()).hexdigest()} for p, (o, u) in edits.items()}
(work/'edits.json').write_text(json.dumps(meta, indent=2)+'\n')
# check-runtime50-uffd-target24.py takes a one-entry edits file for the product makefile.
mk = str(dev/'lineage_gta3xlwifi.mk')
(work/'makefile-edit.json').write_text(json.dumps({mk: meta[mk]}, indent=2)+'\n')
(work/'kernel-digest.json').write_text(json.dumps({'kernel_before': old, 'kernel_after': new}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    for path, (o, u) in edits.items():
        path.write_text(u)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for path, (o, u) in edits.items():
        path.write_text(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
r = dict(sel)
p = art/'runtime53-inputs-20261123-01/report.json'
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p))
out = art/'runtime53-inputs-20261123-02'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot53 SD-card storage props + kernel guard:', after)
