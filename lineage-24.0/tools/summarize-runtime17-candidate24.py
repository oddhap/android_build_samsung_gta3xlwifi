#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind actual build/package proofs for the guarded SM-T510 test candidate."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
A=Path('/srv/android/artifacts/lineage-24.0-arm64');L=Path('/srv/android/logs/lineage-24.0-arm64')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
paths={'geometry':A/'runtime17-product-checks-20261117-01/geometry-policy.json','hooks':A/'runtime17-product-checks-20261117-01/hooks/report.json','ext4':A/'runtime17-product-checks-20261117-01/ext4/report.json','strict':A/'ion-policy-strict-20261117-02/strict/report.json','assertions':A/'ion-policy-strict-20261117-02/assertions.json','vendor':A/'ion-vendor-composition-20261117-01/report.json','container':A/'runtime17-ota-container-20261117-01/report.json','blocks':A/'runtime17-ota-blocks-20261117-01/report.json','vintf':A/'runtime17-vintf-20261117-01/vintf/report.json'}
paths['firststage']=A/'runtime17-product-checks-20261117-01/firststage.json'
paths['cpuacct-root']=A/'runtime17-product-checks-20261117-01/cpuacct-root.json'
paths['vold-metadata']=A/'runtime17-product-checks-20261117-01/vold-metadata.json'
paths['bpf-version']=A/'runtime17-product-checks-20261117-01/bpf-version.json'
paths['netd-oneshot']=A/'runtime17-product-checks-20261117-01/netd-oneshot.json'
paths['netd-first-guards']=A/'runtime17-product-checks-20261117-01/netd-first-guards.json'
paths['legacy-gralloc']=A/'runtime17-product-checks-20261117-01/legacy-gralloc.json'
paths['ion']=A/'runtime17-product-checks-20261117-01/ion.json'
paths['early-adb']=A/'runtime17-product-checks-20261117-01/early-adb.json'
r={k:json.loads(p.read_text()) for k,p in paths.items()}
assert r['early-adb']['passed']
assert r['ion']['passed']
assert r['legacy-gralloc']['passed']
assert r['netd-first-guards']['passed']
assert r['netd-oneshot']['passed']
assert r['bpf-version']['passed']
assert r['vold-metadata']['passed']
assert r['cpuacct-root']['passed']
assert r['firststage']['passed']
for name in ['runtime17-product-build-20261117-01','runtime17-product-checks-20261117-01','ota-tools-build-20261116-01','runtime17-ota-build-20261117-01','runtime17-vintf-20261117-01']:
 assert (L/(name+'.exit')).read_text().strip()=='0'
for k in ['hooks','ext4','assertions','vendor','container','blocks']:assert r[k]['passed']
assert r['geometry']['artifact_checks_passed'] and r['strict']['passed_strict'] and not r['strict']['explicit_input_overrides']
assert r['strict']['results'][0]['neverallow_checks_enabled'] and '-N' not in r['strict']['results'][0]['command']
assert r['vintf']['offline_metadata_passed'] and r['vintf']['factory_apex_count']==39
assert r['assertions']['candidate_assertions_and_constraints']==5881 and not r['assertions']['permissive_domains']
ota=A/'runtime17-ota-build-20261117-01/lineage-24.0-20261117-UNOFFICIAL-gta3xlwifi-test.zip';target=A/'runtime17-ota-build-20261117-01/target-files.zip'
assert sha(ota)==r['container']['ota_sha256']==r['blocks']['ota_sha256']
assert sha(target)==r['geometry']['archive_sha256']==r['container']['target_files_sha256']==r['blocks']['target_files_sha256']==r['vintf']['archive_sha256']
report={'technical_package_checks_passed':True,'ota_filename':ota.name,'ota_bytes':ota.stat().st_size,'ota_sha256':sha(ota),'target_files_sha256':sha(target),'ROM_source_snapshot':'port-20261117-17','packaging_tool_source_snapshot':'port-20261117-17','project_count':1243,'exact_patch_count':21,'proof_reports_sha256':{k:{'path':str(p),'sha256':sha(p)} for k,p in paths.items()},'standard_public_AOSP_development_signature':True,'release_signed':False,'partition_writes':['system','product','vendor','boot'],'recovery_partition_written_by_installer':False,'userdata_wipe_or_repartition':False,'prewrite_recovery_guard':'Recognized exact recovery payload and Android17/2026-10 header required; no automatic header change','remaining_prerequisites':['Fresh signed ZIP must match physically tested installer binaries','Existing recovery must satisfy both prewrite guards at actual installation','Android17 boot, network and encryption require physical test'],'Android17_boot_network_FBE_hardware_tested':False,'flash_ready':False,'owner_device_or_private_keys_accessed_by_package_checks':False}
a.output.write_text(json.dumps(report,indent=2)+'\n');print('PASS technical replacement test-OTA proofs; physical ROM boot remains')
