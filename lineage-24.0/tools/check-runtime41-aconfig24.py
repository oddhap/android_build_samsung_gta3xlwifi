#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Runtime40 variant of the runtime38 check: host proof rebound for the snapshot40 BoardConfig.mk
(product image removed), product members under SYSTEM/product/, strict CIL input paths mapped
from product/ to system/product/ with identical content, fstab = runtime19 with only the /product line replaced.
Bind real packaged metadata storage, flag values and unchanged strict policy to the new bootstrap."""
import argparse,hashlib,json,stat,subprocess,zipfile
from pathlib import Path
def moved(path):
 # Snapshot40 folds product into system. Map a recorded product output path to its
 # system/product location and require the stale product location to be gone.
 s=str(path);old='/out/target/product/gta3xlwifi/product/';new='/out/target/product/gta3xlwifi/system/product/'
 if old not in s:return Path(s)
 assert not Path(s).exists(),('Stale separate product output still present',s)
 return Path(s.replace(old,new))
FSTAB_W=json.loads(Path('/srv/android/artifacts/lineage-24.0-arm64/runtime40-product-in-system-selection-20261121-01/replacements.json').read_text())['fstab.exynos7904']
def fstab40(b):
 for old,new in FSTAB_W:
  assert b.count(old.encode())==1;b=b.replace(old.encode(),new.encode())
 return b
p=argparse.ArgumentParser()
for n in ['top','archive','geometry','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();A=Path('/srv/android/artifacts/lineage-24.0-arm64')
def sha(f):
 h=hashlib.sha256()
 with f.open('rb') as s:
  for b in iter(lambda:s.read(1048576),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256'];host=A/'runtime40-boardconfig-rebind-20261121-01/aconfig-host-report.json';h=json.loads(host.read_text());assert h['passed'] and not h['compiled_policy_rules_changed'] and not h['flag_values_or_services_disabled'];ctx=a.geometry.parent/'contexts/report.json';c=json.loads(ctx.read_text());assert c['passed']
for name,x in c['inputs_sha256'].items():assert sha(Path(name))==x
for name,x in h['source_sha256'].items():assert sha(a.top/name)==x
for name,x in h['inputs_sha256'].items():assert sha(Path(name))==x
strict=A/'gmsion-policy-strict-20261121-01/strict/report.json';r=json.loads(strict.read_text());assert r['passed_strict'] and not r['explicit_input_overrides']
for item in r['inputs']:assert sha(moved(item['path']))==item['sha256'],'Compiled policy inputs changed: fresh cache review required'
policy=strict.parent/'strict.policy';assert sha(policy)==r['results'][0]['compiled_policy_sha256'];vendor=json.loads((A/'gmsion-vendor-20261121-01/report.json').read_text());assert vendor['strict_policy_sha256']==sha(policy)
with zipfile.ZipFile(a.archive) as z:
 info=z.getinfo('ROOT/metadata/');assert stat.S_ISDIR(info.external_attr>>16) and not (info.external_attr>>16)&0o022
 rc=z.read('ROOT/init.exynos7904.rc');assert hashlib.sha256(rc).hexdigest()==h['source_sha256']['device/samsung/gta3xlwifi/rootdir/init.exynos7904.rc'];assert b'mount none /cache/gta3xlwifi_metadata /metadata bind' in rc and b'restorecon_recursive /metadata' in rc
 original=z.read('SYSTEM/etc/init/aconfigd.rc');assert hashlib.sha256(original).hexdigest()==h['inputs_sha256'][str(a.top/'out/target/product/gta3xlwifi/system/etc/init/aconfigd.rc')];assert b'on post-fs\n' in original and b'exec_start system_aconfigd_platform_init' in original
 assert z.read('ROOT/fstab.exynos7904')==fstab40(zipfile.ZipFile(A/'runtime19-ota-build-20261117-01/target-files.zip').read('ROOT/fstab.exynos7904'))
 files={};total=0
 for prefix in ['SYSTEM/etc/aconfig/','SYSTEM/system_ext/etc/aconfig/','SYSTEM/product/etc/aconfig/']:
  members=[n for n in z.namelist() if n.startswith(prefix) and not n.endswith('/')];assert members,prefix
  for name in members:
   b=z.read(name);total+=len(b);files[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
 assert total>0 and total*4<64*1024*1024,'Built-in flag tables exceed conservative cache budget'
 flags=a.top/'out/target/product/gta3xlwifi/system/etc/aconfig_flags.pb';assert hashlib.sha256(z.read('SYSTEM/etc/aconfig_flags.pb')).hexdigest()==sha(flags)
 name='android.security.aapm_feature_disable_insecure_wifi_autojoin';cmd=[str(a.top/'out/host/linux-x86/bin/aconfig'),'dump','--cache',str(flags),'--filter','fully_qualified_name:'+name,'--format','{fully_qualified_name} {state:bool} {permission} {container}'];flag=subprocess.run(cmd,capture_output=True,text=True,check=True).stdout.strip();assert flag==h['actual_security_flag']==name+' true READ_ONLY system'
 pctx=z.read('SYSTEM/system_ext/etc/selinux/system_ext_file_contexts').decode();assert '/cache/gta3xlwifi_metadata/aconfig' in pctx
report=dict(passed=True,scope=__doc__,archive_sha256=g['archive_sha256'],root_metadata_directory_present=True,root_metadata_not_group_or_world_writable=True,packaged_bootstrap_sha256=hashlib.sha256(rc).hexdigest(),builtin_aconfig_tables=files,builtin_flag_table_bytes=total,actual_security_flag=flag,fresh_actual_contexts_report_sha256=sha(ctx),strict_CIL_inputs_match_fresh_policy=True,strict_policy_sha256=sha(policy),vendor_cache_matches_fresh_policy=True,userdata_fstab_line_identical=True,product_mount_removed=True,partitions_formatted_or_resized=False,flag_services_or_values_disabled=False,host_proof_sha256=sha(host),hardware_metadata_backend_proven=False,flash_ready=False);a.output.write_text(json.dumps(report,indent=2)+'\n');print('PASS real packaged metadata mountpoint/bootstrap/tables, true protection flag, fresh contexts and fresh strict policy/cache')
