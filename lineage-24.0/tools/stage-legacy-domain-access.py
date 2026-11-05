#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Narrow invalid netd process-label writes and retire absent legacy components.

Installed-name inventories cover the immutable diagnostic system archive and
extracted selected vendor. This is not a runtime service/provider validation.
All domain declarations, labels, assertions and normal proc read/FD access stay.
"""
import argparse,hashlib,importlib.util,json,zipfile
from pathlib import Path
def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.baseline.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
paths=[Path(x['path']) for x in base['inputs'] if Path(x['path']).name=='vendor_sepolicy.cil'];assert len(paths)==1
src=paths[0]
for item in base['inputs']:assert sha(Path(item['path']))==item['sha256']
vendor=Path('/srv/android/artifacts/lineage-24.0-arm64/vendor-check-20261101-01/vendor')
archive=Path('/srv/android/artifacts/lineage-24.0-arm64/diagnostic-full-targetfiles-preserve-20261103-02/lineage_gta3xlwifi-target_files.zip')
with zipfile.ZipFile(archive) as z:names=sorted(z.namelist())
vendor_names=sorted(str(p.relative_to(vendor)) for p in vendor.rglob('*') if p.is_file())
retired_programs={'irisd','iorapd','iorap_inode2filename','iorap_prefetcherd'}
assert not [n for n in names+vendor_names if Path(n).name in retired_programs]
manifests={str(p):p.read_text() for p in (vendor/'etc/vintf').rglob('*.xml')}
assert not any('android.hardware.automotive.vehicle' in t or 'vendor.samsung.hardware.biometrics.iris' in t for t in manifests.values())
assert not any('automotive.vehicle' in n or 'vehicle-service' in n for n in vendor_names)
changes={
 '(allow netd_30_0 netd_30_0 (file (ioctl read write create getattr setattr lock append map unlink rename open watch watch_reads)))':
 '(allow netd_30_0 netd_30_0 (file (ioctl read write getattr setattr lock append map unlink rename open watch watch_reads)))',
 '(allow netd_30_0 netd_30_0 (dir (write lock open add_name remove_name search)))':
 '(allow netd_30_0 netd_30_0 (dir (lock open search)))',
 '(allow netd_30_0 vendor_samsung_port_nonbpf_proc (filesystem (associate)))':'',
 '(allow hal_vehicle_default hal_can_bus_hwservice_30_0 (hwservice_manager (find)))':''}
original=src.read_text()
for old in changes:assert original.splitlines().count(old)==1
retired_sources={'irisd','iorapd_30_0','iorap_inode2filename_30_0','iorap_prefetcherd_30_0'}
pieces=[];end=0;ledger=[]
for kind,start,stop in forms.statements(original,cil.tokens):
 if kind not in ['allow','allowx','allowxperm']:continue
 text=original[start:stop];ts=cil.tokens(text)
 if text in changes:replacement=changes[text];reason='Android17 process-label/proc association or unavailable automotive client boundary'
 elif ts[2][1] in retired_sources:replacement='';reason='No legacy provider executable in current diagnostic system or selected vendor inventory'
 else:continue
 if replacement:
  new=[t[1] for t in cil.tokens(replacement)];old=[t[1] for t in ts]
  assert old[:7]==new[:7] and set(new[7:-3])<set(old[7:-3])
 pieces.extend([original[end:start],replacement]);end=stop
 ledger.append({'kind':kind,'before':text,'after':replacement,'reason':reason})
pieces.append(original[end:]);staged=''.join(pieces)
assert any(x['before'].startswith('(allow irisd ') for x in ledger)
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(src.parent) and not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged)
report={'scope':__doc__,'changes':ledger,'retired_program_names':sorted(retired_programs),
 'system_archive_inventory_sha256':hashlib.sha256('\n'.join(names).encode()).hexdigest(),
 'system_archive_path':str(archive),'archive_hash_reference_from_prior_full_check':'5d6d30884abdf5c9cd2ea1680961005f681598a508bcb0937d6ebb27bebc3b45',
 'whole_archive_rehashed_by_this_tool':False,
 'vendor_file_inventory_sha256':hashlib.sha256('\n'.join(vendor_names).encode()).hexdigest(),
 'manifest_sha256':{p:sha(Path(p)) for p in manifests},'runner_sha256':sha(Path(__file__)),
 'source_sha256':sha(src),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
 'allow_permissions_added':False,'runtime_provider_or_feature_coverage_proved':False,
 'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');assert src.read_text()==original
print('STAGED: process-label permission subsets and absent legacy component grants retired:',len(ledger),'changes')
