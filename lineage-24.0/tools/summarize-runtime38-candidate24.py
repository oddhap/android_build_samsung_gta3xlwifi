#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind actual build/package proofs for the guarded SM-T510 test candidate."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--container',type=Path,required=True);p.add_argument('--blocks',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
A=Path('/srv/android/artifacts/lineage-24.0-arm64');L=Path('/srv/android/logs/lineage-24.0-arm64')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
paths={'geometry':A/'runtime38-product-checks-20261121-02/geometry-policy.json','hooks':A/'runtime38-product-checks-20261121-02/hooks/report.json','ext4':A/'runtime38-product-checks-20261121-02/ext4/report.json','strict':A/'ion2-policy-strict-20261120-01/strict/report.json','assertions':A/'ion2-policy-strict-20261120-01/assertions.json','vendor':A/'btaudio-vendor-20261120-01/report.json','container':a.container,'blocks':a.blocks,'vintf':A/'runtime38-vintf-20261121-01/vintf/report.json'}
paths['firmware-labels']=A/'ion2-built-labels-20261120-01/report.json'
paths['firmware-access']=A/'ion2-built-access-20261120-01/report.json'
paths['firststage']=A/'runtime38-product-checks-20261121-02/firststage.json'
paths['cpuacct-root']=A/'runtime38-product-checks-20261121-02/cpuacct-root.json'
paths['vold-metadata']=A/'runtime38-product-checks-20261121-02/vold-metadata.json'
paths['bpf-version']=A/'runtime38-product-checks-20261121-02/bpf-version.json'
paths['netd-oneshot']=A/'runtime38-product-checks-20261121-02/netd-oneshot.json'
paths['netd-first-guards']=A/'runtime38-product-checks-20261121-02/netd-first-guards.json'
paths['legacy-gralloc']=A/'runtime38-product-checks-20261121-02/legacy-gralloc.json'
paths['ion']=A/'runtime38-product-checks-20261121-02/ion.json'
paths['early-adb']=A/'runtime38-product-checks-20261121-02/early-adb.json'
paths['aconfig-cache']=A/'runtime38-product-checks-20261121-02/aconfig-cache.json'
paths['fresh-contexts']=A/'runtime38-product-checks-20261121-02/contexts/report.json'
paths['clat-bootstrap']=A/'runtime38-product-checks-20261121-02/clat-bootstrap.json'
paths['local-note-listener']=A/'runtime38-product-checks-20261121-02/local-note-listener.json'
paths['lmkd']=A/'runtime38-product-checks-20261121-02/lmkd.json'
paths['display-keyboard']=A/'runtime38-product-checks-20261121-02/ui.json'
paths['touch-wake']=A/'runtime38-product-checks-20261121-02/touch-wake.json'
paths['network-access-wait']=A/'runtime38-product-checks-20261121-02/network-access-wait.json'
paths['log-noise']=A/'runtime38-product-checks-20261121-02/log-noise.json'
paths['boot-security-patch']=A/'runtime38-product-checks-20261121-02/boot-security-patch.json'
paths['boardconfig-rebind']=A/'runtime38-boardconfig-rebind-20261121-02/report.json'
r={k:json.loads(p.read_text()) for k,p in paths.items()}
assert r['network-access-wait']['passed'] and r['log-noise']['passed'] and r['boardconfig-rebind']['passed']
b=r['boot-security-patch'];assert b['passed'] and b['boot_os_version_word']=='0x220001ab' and b['boot_security_patch']=='2026-11-01' and b['system_security_patch']==b['platform_security_patch']==r['geometry']['security_patch']
assert r['geometry']['images']['boot.img']['os_version_word']==0x220001ab
assert r['lmkd']['passed'] and r['display-keyboard']['passed'] and r['touch-wake']['passed']
assert r['local-note-listener']['passed']
assert r['clat-bootstrap']['passed']
assert r['aconfig-cache']['passed'] and r['fresh-contexts']['passed']
assert r['early-adb']['passed']
assert r['ion']['passed']
assert r['legacy-gralloc']['passed']
assert r['netd-first-guards']['passed']
assert r['netd-oneshot']['passed']
assert r['bpf-version']['passed']
assert r['vold-metadata']['passed']
assert r['cpuacct-root']['passed']
assert r['firststage']['passed']
for name in ['runtime38-product-build-20261121-01','runtime38-product-checks-20261121-02','ota-tools-build-20261116-01','runtime38-ota-build-20261121-01','runtime38-vintf-20261121-01']:
 assert (L/(name+'.exit')).read_text().strip()=='0'
for k in ['hooks','ext4','assertions','vendor','container','blocks','firmware-labels','firmware-access']:assert r[k]['passed']
assert r['geometry']['artifact_checks_passed'] and r['strict']['passed_strict'] and not r['strict']['explicit_input_overrides']
assert r['strict']['results'][0]['neverallow_checks_enabled'] and '-N' not in r['strict']['results'][0]['command']
assert r['vintf']['offline_metadata_passed'] and r['vintf']['factory_apex_count']==39
assert r['assertions']['candidate_assertions_and_constraints']==5881 and not r['assertions']['permissive_domains']
ota=A/'runtime38-ota-build-20261121-01/lineage-24.0-20261121-UNOFFICIAL-gta3xlwifi-test.zip';target=A/'runtime38-ota-build-20261121-01/target-files.zip'
assert sha(ota)==r['container']['ota_sha256']==r['blocks']['ota_sha256']
assert sha(target)==r['geometry']['archive_sha256']==r['container']['target_files_sha256']==r['blocks']['target_files_sha256']==r['vintf']['archive_sha256']
report={'technical_package_checks_passed':True,'legacy_local_network_note_ops_available':False,'ota_filename':ota.name,'ota_bytes':ota.stat().st_size,'ota_sha256':sha(ota),'target_files_sha256':sha(target),'ROM_source_snapshot':'port-20261121-38','upstream_lineage_sync':'2026-11-20 (snapshot port-20261120-31-sync)','packaging_tool_source_snapshot':'port-20261121-38','project_count':1244,'exact_patch_count':24,'proof_reports_sha256':{k:{'path':str(p),'sha256':sha(p)} for k,p in paths.items()},'standard_public_AOSP_development_signature':True,'release_signed':False,'partition_writes':['system','product','vendor','boot'],'recovery_partition_written_by_installer':False,'userdata_wipe_or_repartition':False,'prewrite_recovery_guard':'Recognized exact recovery payload and Android17/2026-11 header (fixed boot image patch level 0x220001ab) required; no automatic header change','boot_security_patch':'2026-11-01','boot_header_decoupled_from_system_patch':True,'remaining_prerequisites':['Fresh signed ZIP must match physically tested installer binaries','Existing recovery must satisfy both prewrite guards at actual installation','Android17 boot, network and encryption require physical test'],'Android17_boot_network_FBE_hardware_tested':False,'flash_ready':False,'owner_device_or_private_keys_accessed_by_package_checks':False}
a.output.write_text(json.dumps(report,indent=2)+'\n');print('PASS technical replacement test-OTA proofs; physical ROM boot remains')
