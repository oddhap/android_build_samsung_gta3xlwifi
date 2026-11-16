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
paths={'geometry':A/'installer-product-checks-20261116-01/geometry-policy.json','hooks':A/'installer-product-checks-20261116-01/hooks/report.json','ext4':A/'installer-product-checks-20261116-01/ext4/report.json','strict':A/'policy-composition-strict-20261116-01/strict/report.json','assertions':A/'policy-composition-strict-20261116-01/assertions.json','vendor':A/'vendor-composition-20261116-01/report.json','container':A/'test-ota-container-20261116-01/report.json','blocks':A/'test-ota-block-streams-20261116-02/report.json','vintf':A/'installer-vintf-20261116-01/vintf/report.json'}
r={k:json.loads(p.read_text()) for k,p in paths.items()}
for name in ['installer-product-build-20261116-01','installer-product-checks-20261116-01','ota-tools-build-20261116-01','test-ota-build-20261116-02','installer-vintf-20261116-01']:
 assert (L/(name+'.exit')).read_text().strip()=='0'
for k in ['hooks','ext4','assertions','vendor','container','blocks']:assert r[k]['passed']
assert r['geometry']['artifact_checks_passed'] and r['strict']['passed_strict'] and not r['strict']['explicit_input_overrides']
assert r['strict']['results'][0]['neverallow_checks_enabled'] and '-N' not in r['strict']['results'][0]['command']
assert r['vintf']['offline_metadata_passed'] and r['vintf']['factory_apex_count']==39
assert r['assertions']['candidate_assertions_and_constraints']==5881 and not r['assertions']['permissive_domains']
ota=A/'test-ota-build-20261116-02/lineage-24.0-20261116-UNOFFICIAL-gta3xlwifi-test.zip';target=A/'test-ota-build-20261116-02/target-files.zip'
assert sha(ota)==r['container']['ota_sha256']==r['blocks']['ota_sha256']
assert sha(target)==r['geometry']['archive_sha256']==r['container']['target_files_sha256']==r['blocks']['target_files_sha256']==r['vintf']['archive_sha256']
report={'technical_package_checks_passed':True,'ota_filename':ota.name,'ota_bytes':ota.stat().st_size,'ota_sha256':sha(ota),'target_files_sha256':sha(target),'ROM_source_snapshot':'port-20261116-02','packaging_tool_source_snapshot':'port-20261116-03','project_count':1243,'exact_patch_count':21,'proof_reports_sha256':{k:{'path':str(p),'sha256':sha(p)} for k,p in paths.items()},'standard_public_AOSP_development_signature':True,'release_signed':False,'partition_writes':['system','product','vendor','boot'],'recovery_partition_written_by_installer':False,'userdata_wipe_or_repartition':False,'prewrite_recovery_guard':'Recognized exact recovery payload and Android17/2026-10 header required; no automatic header change','remaining_prerequisites':['Verified current userdata backup and a reviewed recovery/FBE test plan','Existing recovery must satisfy the genuine matching-header guard before installation','New authorization is required for any actual flashing/recovery metadata change'],'Android17_boot_network_FBE_hardware_tested':False,'flash_ready':False,'owner_device_or_private_keys_accessed_by_package_checks':False}
a.output.write_text(json.dumps(report,indent=2)+'\n');print('PASS technical test-OTA proofs; recovery/backup authorization remains')
