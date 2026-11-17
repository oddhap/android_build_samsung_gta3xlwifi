#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import json,hashlib,shutil
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');O=A/'ion-compat-source-composition-20261117-01';assert not O.exists();O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
proof=A/'ion-compat-access-20261117-01/report.json';r=json.loads(proof.read_text());assert r['passed'] and r['no_permissive_domains']
files={};root='device/samsung/gta3xlwifi/sepolicy/private/'
for name in ['file_contexts','gta3xlwifi_ion.te']:
 rel=root+name;dst=O/'files'/rel;dst.parent.mkdir(parents=True,exist_ok=True);old=T/rel
 if name=='file_contexts':
  data=old.read_bytes();assert b'/dev/ion' not in data;new=data+b'\n# Retained Samsung Mali allocator uses the legacy ION device.\n/dev/ion -c u:object_r:ion_device:s0\n';before=sha(old);backup=O/'baseline'/rel;backup.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(old,backup)
 else:
  assert not old.exists();before=None;new=b'# Samsung Mali HIDL2 clients on the retained Linux4.4 ION allocator.\n# Restore the legacy read interface only for the actual graphics clients.\n# Keep current Android17 and Samsung assertions and enforcement intact.\nallow { hal_graphics_allocator_default hal_graphics_composer_default surfaceflinger } ion_device:chr_file r_file_perms;\n'
 dst.write_bytes(new);files[rel]={'before':before,'after':sha(dst)}
(O/'selection.json').write_text(json.dumps({'files':files,'proof_reports_sha256':{str(proof):sha(proof)},'scope':'Exact character-device ION label and three concrete graphics clients; no generic-device grants, no new write grants, assertions unchanged.'},indent=2)+'\n')
# Freeze the prior split-policy inputs before a subsequent source build replaces output CIL.
R=A/'ion-policy-baseline-20261117-01';R.mkdir();old=A/'policy-composition-strict-20261116-01/strict/report.json';r=json.loads(old.read_text());command=r['results'][0]['command']
for i,x in enumerate(r['inputs']):
 src=Path(x['path']);assert sha(src)==x['sha256'];dest=R/(str(i)+'-'+src.name);shutil.copyfile(src,dest);command=[str(dest) if z==str(src) else z for z in command];x['path']=str(dest)
shutil.copyfile(old.parent/'strict.policy',R/'strict.policy');r['results'][0]['command']=command;r['frozen_from_report_sha256']=sha(old);(R/'report.json').write_text(json.dumps(r,indent=2)+'\n')
print('Prepared two explicit source files and immutable assertion baseline')
