#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Require actual rebuilt dual-ABI libui with the genuine configured legacy mapper path."""
import argparse,hashlib,json,subprocess,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','archive','geometry','host-proof','reference','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());r=json.loads(a.host_proof.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256']
assert r['boolean_config_registration_validated'];assert sha(a.top/'build/make/core/config.mk')==r['production_make_config_sha256'];assert r['passed'] and r['legacy_path_requires_actual_loaded_mapper'] and r['no_available_mapper_remains_fatal'] and r['modern_mapper_preference_preserved']
for name,h in r['source_sha256'].items():assert sha(a.top/name)==h
assert sha(a.top/'frameworks/native/libs/ui/GraphicBufferMapper.cpp')==r['unchanged_mapper_source_sha256']
assert sha(a.top/'frameworks/native/libs/ui/Android.bp')==r['unchanged_android_bp_sha256']
config=a.top/'out/soong/soong.lineage_gta3xlwifi.variables';v=json.loads(config.read_text());assert v['VendorVars']['libui']['legacy_gralloc']=='true';assert v['VendorVarTypes']['libui']['legacy_gralloc']=='bool'
objects=[]
base=a.top/'out/soong/.intermediates/frameworks/native/libs/ui/libui'
for variant in ['android_arm64_armv8-a_shared','android_arm_armv8-a_shared']:
 obj=base/variant/'obj/frameworks/native/libs/ui/GraphicBufferMapper.o';assert obj.is_file();objects.append(str(obj.relative_to(a.top)))
cmd=['prebuilts/build-tools/linux-x86/bin/ninja','-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands',*objects]
x=subprocess.run(cmd,cwd=a.top,capture_output=True,text=True,check=True);commands=[line for line in x.stdout.splitlines() if 'GraphicBufferMapper.cpp' in line and 'clang' in line]
assert len(commands)>=2
for obj in objects:assert any(obj in line and '-DLEGACY_GRALLOC' in line for line in commands)
files={}
with zipfile.ZipFile(a.archive) as z,zipfile.ZipFile(a.reference) as old:
 for name in ['SYSTEM/lib64/libui.so','SYSTEM/lib/libui.so']:
  b=z.read(name);h=hashlib.sha256(b).hexdigest();previous=hashlib.sha256(old.read(name)).hexdigest();assert h!=previous
  assert sha(a.top/'out/target/product/gta3xlwifi'/name.lower().split('/')[0]/'/'.join(name.split('/')[1:]))==h
  files[name]={'sha256':h,'bytes':len(b),'reference_sha256':previous}
report={'passed':True,'scope':__doc__,'archive_sha256':g['archive_sha256'],'actual_libui_files':files,'actual_compiler_commands':commands,'actual_soong_config_sha256':sha(config),'host_proof_sha256':sha(a.host_proof),'actual_HAL_load_required':True,'API_properties_unchanged_by_selection':True,'hardware_graphics_or_boot_proven':False,'flash_ready':False};a.output.write_text(json.dumps(report,indent=2)+'\n');print('PASS actual dual-ABI rebuilt libui, production legacy flag and retained mandatory HAL loading')
