#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged ART artifacts to the snapshot50 PRODUCT_ENABLE_UFFD_GC := false change.

Usage: check-runtime50-uffd-target24.py TOP ARCHIVE GEOMETRY EDITS OUTPUT

Background: the 4.4 kernel has no userfaultfd, so the ART runtime falls back to the
concurrent-copying (read-barrier) GC. With PRODUCT_ENABLE_UFFD_GC "default" and no
kernel version file the build assumed CMC (uffd_gc_utils: '<unknown-kernel>' -> True)
and dexpreopted every boot image / odex with -Xgc:CMC (oat header
concurrent-copying=false). The runtime rejects such code as non-executable
("read barrier state mismatch"), so the framework and all apps ran interpreted/JIT.

Requires: the product makefile equals the staged after-hash; ro.dalvik.vm.enable_uffd_gc
is exactly "false" in the packaged build props; no packaged build prop says true; every
packaged .oat/.odex that carries the concurrent-copying oat-header key says "true",
none says "false"; the primary arm and arm64 boot.oat, SystemUI and Launcher3 odex carry
the key; no oat/odex records -Xgc:CMC. Package check only; the device proof is the
oat mmap size of SystemUI and the absence of artd read-barrier mismatches.
"""
import hashlib
import json
from pathlib import Path
import sys
import zipfile

top, archive, geometry, edits, output = map(Path, sys.argv[1:])
assert not output.exists()
g = json.loads(geometry.read_text())
assert g['artifact_checks_passed']
h = hashlib.sha256()
with archive.open('rb') as f:
    for block in iter(lambda: f.read(1 << 20), b''):
        h.update(block)
assert h.hexdigest() == g['archive_sha256'], 'Archive differs from the checked geometry report'
e = json.loads(edits.read_text())
(makefile, meta), = e.items()
makefile = Path(makefile)
assert makefile == top/'device/samsung/gta3xlwifi/lineage_gta3xlwifi.mk'
assert hashlib.sha256(makefile.read_bytes()).hexdigest() == meta['after_sha256'], 'Makefile is not the staged text'
assert makefile.read_text().count('\nPRODUCT_ENABLE_UFFD_GC := false\n') == 1
KEY = b'concurrent-copying\x00'
required = ['SYSTEM/framework/arm64/boot.oat', 'SYSTEM/framework/arm/boot.oat',
            'SYSTEM/system_ext/priv-app/SystemUI/oat/arm64/SystemUI.odex',
            'SYSTEM/system_ext/priv-app/Launcher3QuickStep/oat/arm64/Launcher3QuickStep.odex']
result = {'passed': False, 'makefile_sha256': meta['after_sha256'], 'props': {}, 'oat_files': 0,
          'with_cc_key': {}, 'without_cc_key': 0}
with zipfile.ZipFile(archive) as z:
    for name in z.namelist():
        if name.endswith('build.prop') or name.endswith('/default.prop'):
            for line in z.read(name).decode(errors='replace').splitlines():
                if line.startswith('ro.dalvik.vm.enable_uffd_gc='):
                    result['props'][name] = line.split('=', 1)[1]
        if not name.endswith(('.oat', '.odex')):
            continue
        data = z.read(name)
        result['oat_files'] += 1
        assert b'-Xgc:CMC' not in data, 'CMC dex2oat flag recorded in ' + name
        i = data.find(KEY)
        if i < 0:
            result['without_cc_key'] += 1
            continue
        value = data[i+len(KEY):data.index(b'\x00', i+len(KEY))].decode()
        assert data.count(KEY) == 1, name
        result['with_cc_key'][name] = value
assert result['props'] and set(result['props'].values()) == {'false'}, result['props']
bad = {n: v for n, v in result['with_cc_key'].items() if v != 'true'}
assert not bad, f'{len(bad)} oat/odex not compiled for the read-barrier GC, e.g. {sorted(bad)[:5]}'
missing = [n for n in required if n not in result['with_cc_key']]
assert not missing, missing
result['passed'] = True
result['runtime_tested'] = False
output.write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
print('PASS ART artifacts compiled for the concurrent-copying GC:', len(result['with_cc_key']), 'oat/odex')
