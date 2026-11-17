#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Restore the upstream old-vendor libcutils ashmem interface and observed bootanim ION access.
The direct legacy /dev/ashmem open restriction remains enforced. No memfd
capability, vendor API, property or networking readiness is fabricated.
"""
from pathlib import Path
import hashlib,json
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');O=A/'legacy-shm-source-composition-20261117-01';O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files={};prefix='device/samsung/gta3xlwifi/sepolicy/private/'
f=prefix+'gta3xlwifi_ion.te';b=T/f;s=b.read_text();needle='hal_graphics_allocator_server hal_graphics_composer_server surfaceflinger';assert s.count(needle)==1;s=s.replace(needle,needle+' bootanim')
for kind in ['baseline','files']:
 d=O/kind/f;d.parent.mkdir(parents=True,exist_ok=True);d.write_text(b.read_text() if kind=='baseline' else s)
files[f]={'before':sha(b),'after':sha(O/'files'/f)}
f=prefix+'gta3xlwifi_legacy_ashmem.te';assert not (T/f).exists();d=O/'files'/f;d.parent.mkdir(parents=True,exist_ok=True)
u=T/'system/sepolicy/vendor/ashmem/ashmem_allow.te';assert 'allow domain ashmem_libcutils_device:chr_file open;' in u.read_text()
d.write_text('''# Retained Samsung vendor API28 predates the Android17 ashmem/memfd transition.
# Same old-vendor compatibility rule as system/sepolicy/vendor/ashmem/ashmem_allow.te.
# The prebuilt vendor cannot carry this newly introduced platform type itself.
# Only the libcutils API node gains open; direct ashmem_device restrictions stay.
# Keep all Android17 and Samsung assertions; never force unsupported memfd use.
allow domain ashmem_libcutils_device:chr_file open;
''');files[f]={'before':None,'after':sha(d)}
(O/'selection.json').write_text(json.dumps({'files':files,'scope':__doc__,'upstream_old_vendor_rule_sha256':sha(u),'direct_ashmem_device_restrictions_changed':False},indent=2)+'\n')
