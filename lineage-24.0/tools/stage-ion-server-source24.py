#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib,json,shutil
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');O=A/'ion-server-source-composition-20261117-01';O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
f='device/samsung/gta3xlwifi/sepolicy/private/gta3xlwifi_ion.te';b=T/f;s=b.read_text();assert 'hal_graphics_allocator_default hal_graphics_composer_default surfaceflinger' in s;s=s.replace('hal_graphics_allocator_default hal_graphics_composer_default','hal_graphics_allocator_server hal_graphics_composer_server')
for kind in ['baseline','files']:
 d=O/kind/f;d.parent.mkdir(parents=True,exist_ok=True);d.write_text(b.read_text() if kind=='baseline' else s)
# Verify these public server attributes denote exactly the intended concrete vendors.
for attr,typ in [('hal_graphics_allocator_server','hal_graphics_allocator_default'),('hal_graphics_composer_server','hal_graphics_composer_default')]:
 rows=[line for c in (A/'ion-policy-baseline-20261117-01').glob('*.cil') for line in c.read_text().splitlines() if line.startswith('(typeattributeset '+attr+' ')];assert rows==['(typeattributeset '+attr+' ('+typ+'))'],rows
(O/'selection.json').write_text(json.dumps({'files':{f:{'before':sha(b),'after':sha(O/'files'/f)}},'scope':'Use the public server attributes visible to system_ext. Actual retained vendor memberships are exactly the same two concrete graphics services; clients remain excluded.'},indent=2)+'\n')
