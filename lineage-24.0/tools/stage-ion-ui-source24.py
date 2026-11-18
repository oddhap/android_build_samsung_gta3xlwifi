#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage only the legacy ION read interface for five physically observed clients.
Retain every current Android17/Samsung assertion, vendor identity and rendering
guard. No generic-device or write grant is added. The existing trusted graphics
clients and old-vendor ashmem compatibility remain unchanged.
"""
from pathlib import Path
import hashlib,json
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');O=A/'ion-ui-source-composition-20261117-01';assert not O.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=json.loads((A/'ion-ui-clients-access-20261117-01/report.json').read_text());assert r['passed'] and r['no_permissive_domains']
r=json.loads((A/'ion-ui-clients-probe-20261117-01/report.json').read_text());clients=['system_server','mediaswcodec','platform_app','priv_app','system_app'];assert r['passed_strict'] and r['observed_clients']==clients and r['no_neverallow_bypass'] and r['no_new_write_grants']
cil=A/'ion-ui-clients-probe-20261117-01/observed-ion-ui-clients.cil';assert cil.read_text()==''.join('(allow '+s+' ion_device (chr_file (getattr open read ioctl lock map watch watch_reads)))\n' for s in clients)
rel='device/samsung/gta3xlwifi/sepolicy/private/gta3xlwifi_ion.te';old=(T/rel).read_text();assert 'system_server' not in old and 'mediaswcodec' not in old
new=old+'''\n# Physical Android17 first UI: these clients fail ion_open with EACCES.
# Scope the retained allocator read API to the observed platform clients only.
# Keep rendering-failure guards, generic device denials and all assertions.
allow { system_server mediaswcodec platform_app priv_app system_app } ion_device:chr_file r_file_perms;
'''
O.mkdir()
for folder,text in [('baseline',old),('files',new)]:
 f=O/folder/rel;f.parent.mkdir(parents=True);f.write_text(text)
(O/'selection.json').write_text(json.dumps(dict(scope=__doc__,files={rel:dict(before=sha(T/rel),after=sha(O/'files'/rel))},observed_clients=clients,new_write_grants=False,generic_device_grants=False,neverallow_bypass=False),indent=2)+'\n');print('Staged one policy source, exact five observed ION clients')
