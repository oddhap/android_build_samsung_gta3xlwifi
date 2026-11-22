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
paths={'geometry':A/'runtime44-product-checks-20261121-01/geometry-policy.json','hooks':A/'runtime44-product-checks-20261121-01/hooks/report.json','ext4':A/'runtime44-product-checks-20261121-01/ext4/report.json','strict':A/'gmsion-policy-strict-20261121-01/strict/report.json','assertions':A/'gmsion-policy-strict-20261121-01/assertions.json','vendor':A/'gmsion-vendor-20261121-01/report.json','container':a.container,'blocks':a.blocks,'vintf':A/'runtime44-vintf-20261121-01/vintf/report.json'}
paths['firmware-labels']=A/'gmsion-built-labels-20261121-01/report.json'
paths['firmware-access']=A/'gmsion-built-access-20261121-01/report.json'
paths['firststage']=A/'runtime44-product-checks-20261121-01/firststage.json'
paths['cpuacct-root']=A/'runtime44-product-checks-20261121-01/cpuacct-root.json'
paths['vold-metadata']=A/'runtime44-product-checks-20261121-01/vold-metadata.json'
paths['bpf-version']=A/'runtime44-product-checks-20261121-01/bpf-version.json'
paths['netd-oneshot']=A/'runtime44-product-checks-20261121-01/netd-oneshot.json'
paths['netd-first-guards']=A/'runtime44-product-checks-20261121-01/netd-first-guards.json'
paths['legacy-gralloc']=A/'runtime44-product-checks-20261121-01/legacy-gralloc.json'
paths['ion']=A/'runtime44-product-checks-20261121-01/ion.json'
paths['early-adb']=A/'runtime44-product-checks-20261121-01/early-adb.json'
paths['aconfig-cache']=A/'runtime44-product-checks-20261121-01/aconfig-cache.json'
paths['fresh-contexts']=A/'runtime44-product-checks-20261121-01/contexts/report.json'
paths['clat-bootstrap']=A/'runtime44-product-checks-20261121-01/clat-bootstrap.json'
paths['local-note-listener']=A/'runtime44-product-checks-20261121-01/local-note-listener.json'
paths['lmkd']=A/'runtime44-product-checks-20261121-01/lmkd.json'
paths['display-keyboard']=A/'runtime44-product-checks-20261121-01/ui.json'
paths['touch-wake']=A/'runtime44-product-checks-20261121-01/touch-wake.json'
paths['network-access-wait']=A/'runtime44-product-checks-20261121-01/network-access-wait.json'
paths['log-noise']=A/'runtime44-product-checks-20261121-01/log-noise.json'
paths['boot-security-patch']=A/'runtime44-product-checks-20261121-01/boot-security-patch.json'
paths['boardconfig-rebind']=A/'runtime40-boardconfig-rebind-20261121-01/report.json'
paths['recovery-identity']=A/'runtime44-product-checks-20261121-01/recovery-identity.json'
paths['product-layout']=A/'runtime44-product-checks-20261121-01/product-layout.json'
paths['recovery-identity-host']=A/'runtime44-recovery-identity-host-20261121-01/report.json'
paths['updater']=A/'runtime44-product-checks-20261121-01/updater.json'
paths['devicemk-rebind']=A/'runtime44-devicemk-rebind-20261121-01/report.json'
r={k:json.loads(p.read_text()) for k,p in paths.items()}
assert r['product-layout']['passed'] and not r['product-layout']['product_image_present']
assert r['recovery-identity']['passed'] and r['recovery-identity-host']['passed']
assert r['updater']['passed'] and r['devicemk-rebind']['passed'] and r['updater']['lineage_updater_uri']==r['devicemk-rebind']['lineage_updater_uri']
assert 'de91185c3dbbed822612c5478780aa0bd4cb1c77c0b20c42e29cd0301b3b65bb' in r['recovery-identity']['known_identities']
assert r['recovery-identity-host']['new_recovery_sha256']=='33875693066aeb5e9f27bc2d469c3052b438552395cb476ed0d8340348765f05'
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
for name in ['runtime44-product-build-20261121-01','runtime44-product-checks-20261121-01','ota-tools-build-20261116-01','runtime44-ota-build-20261121-01','runtime44-vintf-20261121-01']:
 assert (L/(name+'.exit')).read_text().strip()=='0'
for k in ['hooks','ext4','assertions','vendor','container','blocks','firmware-labels','firmware-access']:assert r[k]['passed']
assert r['geometry']['artifact_checks_passed'] and r['strict']['passed_strict'] and not r['strict']['explicit_input_overrides']
assert r['strict']['results'][0]['neverallow_checks_enabled'] and '-N' not in r['strict']['results'][0]['command']
assert r['vintf']['offline_metadata_passed'] and r['vintf']['factory_apex_count']==39
assert r['assertions']['candidate_assertions_and_constraints']==5881 and not r['assertions']['permissive_domains']
otas=sorted((A/'runtime44-ota-build-20261121-01').glob('lineage-24.0-20??????-UNOFFICIAL-gta3xlwifi-test.zip'));assert len(otas)==1;ota=otas[0];target=A/'runtime44-ota-build-20261121-01/target-files.zip'
assert sha(ota)==r['container']['ota_sha256']==r['blocks']['ota_sha256']
assert sha(target)==r['geometry']['archive_sha256']==r['container']['target_files_sha256']==r['blocks']['target_files_sha256']==r['vintf']['archive_sha256']
report={'technical_package_checks_passed':True,'legacy_local_network_note_ops_available':False,'ota_filename':ota.name,'ota_bytes':ota.stat().st_size,'ota_sha256':sha(ota),'target_files_sha256':sha(target),'ROM_source_snapshot':'port-20261121-44','ion_read_added_for':['priv_app_all','gmscore_app'],'kernel':'gate-split (HOLD_UPDATE keeps packet gate open, netpolicy ABI 2)','upstream_lineage_sync':'2026-11-20 (snapshot port-20261120-31-sync)','packaging_tool_source_snapshot':'port-20261121-44','project_count':1244,'exact_patch_count':24,'proof_reports_sha256':{k:{'path':str(p),'sha256':sha(p)} for k,p in paths.items()},'standard_public_AOSP_development_signature':True,'release_signed':False,'partition_writes':['system','vendor','boot'],'product_folded_into_system':True,'physical_product_partition_written':False,'gapps_headroom_kib':r['product-layout']['headroom_after_complete_gapps_kib'],'recovery_partition_written_by_installer':False,'userdata_wipe_or_repartition':False,'recognized_recovery_identities':r['recovery-identity']['known_identities'],'lineage_updater_uri':r['updater']['lineage_updater_uri'],'ota_post_timestamp':int(r['container']['metadata']['post-timestamp']),'addon_d_backup_restore':True,'prewrite_recovery_guard':'Recognized exact recovery payload (incl. owner-approved TWRP 33875693 and 96b3de24) and Android17/2026-11 header (fixed boot image patch level 0x220001ab) required; no automatic header change','boot_security_patch':'2026-11-01','boot_header_decoupled_from_system_patch':True,'remaining_prerequisites':['Fresh signed ZIP must match physically tested installer binaries','Existing recovery must satisfy both prewrite guards at actual installation','Android17 boot, network and encryption require physical test'],'Android17_boot_network_FBE_hardware_tested':False,'flash_ready':False,'owner_device_or_private_keys_accessed_by_package_checks':False}
a.output.write_text(json.dumps(report,indent=2)+'\n');print('PASS technical replacement test-OTA proofs; physical ROM boot remains')
