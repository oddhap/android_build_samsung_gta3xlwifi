#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged services.jar and system property to the snapshot36 wait budget.

Checks: the exact snapshot36 ActivityManagerConstants source is in the tree, the
packaged services.jar dex carries the legacy-backend property key next to the
network_access_timeout_ms key, and the packaged system/product build.prop
selects the legacy backend (ro.gta3xlwifi.legacy_networking=true). This proves
packaging only; the physical resume behavior requires the device test."""
import hashlib, json, sys, zipfile, io
from pathlib import Path
top, archive, geometry, output = map(Path, sys.argv[1:5])
assert not output.exists()
def sha(f):
    h = hashlib.sha256()
    with f.open('rb') as s:
        for b in iter(lambda: s.read(1048576), b''): h.update(b)
    return h.hexdigest()
g = json.loads(geometry.read_text()); assert g['artifact_checks_passed'] and sha(archive) == g['archive_sha256']
src = top/'frameworks/base/services/core/java/com/android/server/am/ActivityManagerConstants.java'
text = src.read_text()
assert text.count('SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)') == 1
assert '? 2000 : 200;' in text and 'DEFAULT_NETWORK_ACCESS_TIMEOUT_MS = 200;' not in text
sel = json.loads((Path('/srv/android/artifacts/lineage-24.0-arm64/runtime36-netaccess-selection-20261120-01/edits.json')).read_text())
assert sel[str(src)]['after_sha256'] == sha(src)
with zipfile.ZipFile(archive) as z:
    jar = z.read('SYSTEM/framework/services.jar')
    props = b''.join(z.read(n) for n in z.namelist() if n.endswith('build.prop') and n.split('/')[0] in ('SYSTEM', 'PRODUCT', 'VENDOR', 'SYSTEM_EXT'))
dex_hits = []
with zipfile.ZipFile(io.BytesIO(jar)) as j:
    for n in j.namelist():
        if n.startswith('classes') and n.endswith('.dex'):
            d = j.read(n)
            if b'ro.gta3xlwifi.legacy_networking' in d and b'network_access_timeout_ms' in d:
                dex_hits.append(n)
assert dex_hits, 'packaged services.jar lacks the snapshot36 wait budget'
assert b'\nro.gta3xlwifi.legacy_networking=true\n' in props
output.write_text(json.dumps(dict(passed=True, scope=__doc__, archive_sha256=g['archive_sha256'],
    source_sha256=sha(src), services_jar_sha256=hashlib.sha256(jar).hexdigest(), dex_members=dex_hits,
    legacy_backend_property_packaged=True, enforcement_changed=False, physical_resume_tested=False), indent=2)+'\n')
print('PASS packaged legacy-backend network-access wait budget')
