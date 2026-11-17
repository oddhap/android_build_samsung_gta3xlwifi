#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provide genuine metadata storage from a dedicated existing cache directory.
The vendor mounts cache on fs. Root hardware-init is imported before service rc
files, so its post-fs bind precedes aconfigd's supported post-fs retry. Existing
cache contents and userdata remain intact; flag values/services stay unchanged.
"""
from pathlib import Path
import hashlib,json
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');O=A/'aconfig-cache-source-composition-20261117-01';O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files={};prefix='device/samsung/gta3xlwifi/'
def stage(rel,new):
 old=T/rel;before=O/'baseline'/rel;dest=O/'files'/rel
 for p in [before,dest]:p.parent.mkdir(parents=True,exist_ok=True)
 before.write_bytes(old.read_bytes());dest.write_text(new);files[rel]=dict(before=sha(old),after=sha(dest))
f=prefix+'BoardConfig.mk';s=(T/f).read_text();assert 'BOARD_ROOT_EXTRA_FOLDERS += metadata' not in s;s+='\n# Immutable SAR root needs the real metadata bind-mount point.\nBOARD_ROOT_EXTRA_FOLDERS += metadata\n';stage(f,s)
f=prefix+'rootdir/init.exynos7904.rc';s=(T/f).read_text();assert '/cache/gta3xlwifi_metadata' not in s;s+='''
# Legacy physical layout: vendor mount_all already mounts cache on fs.
# Hardware init is imported before system service rc files. Populate the real
# metadata view before aconfigd retries on post-fs, retaining compiled flag values.
# Only this new directory is bound; existing cache files and userdata are retained.
on post-fs
    mkdir /cache/gta3xlwifi_metadata 0755 root root
    restorecon_recursive /cache/gta3xlwifi_metadata
    mount none /cache/gta3xlwifi_metadata /metadata bind
    restorecon_recursive /metadata
''';stage(f,s)
platform=T/'system/sepolicy/private/file_contexts';rows=[l for l in platform.read_text().splitlines() if l.startswith('/metadata')];assert rows and all(l.startswith('/metadata/') or l.startswith('/metadata(') for l in rows),rows
f=prefix+'sepolicy/private/file_contexts';s=(T/f).read_text();assert 'gta3xlwifi_metadata' not in s;s+='\n# Dedicated metadata backend on existing cache; mirror every canonical A17 label.\n'+'\n'.join(l.replace('/metadata','/cache/gta3xlwifi_metadata',1) for l in rows)+'\n';stage(f,s)
(O/'selection.json').write_text(json.dumps(dict(files=files,scope=__doc__,canonical_metadata_contexts_sha256=sha(platform),canonical_metadata_rules=rows,compiled_policy_rules_changed=False,flag_values_or_services_disabled=False,partition_layout_changed=False,cache_formatted=False),indent=2)+'\n');print('Staged root mountpoint, ordered metadata bind and exact canonical labels')
