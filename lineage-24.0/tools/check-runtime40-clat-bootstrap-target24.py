#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind rebuilt packaged JNI/aconfigd to exact source regressions and immutable userspace CLAT selection.

Runtime40 variant (only change): /product is folded into /system (snapshot40);
no product image, product members live under SYSTEM/product/."""
import argparse,hashlib,json,subprocess,zipfile,io,tempfile
from pathlib import Path
p=argparse.ArgumentParser()
for n in ['top','archive','geometry','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();T=a.top;A=Path('/srv/android/artifacts/lineage-24.0-arm64')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256'];proof=A/'clat-bootstrap-host-20261117-01/report.json';r=json.loads(proof.read_text());assert r['passed'] and r['native_verification_cases']==79 and r['flag_bootstrap_cases']==197 and r['original_native_abort_reproduced'] and r['original_optional_vendor_failure_reproduced']
for n,h in r['source_sha256'].items():assert sha(T/n)==h
java=T/'packages/modules/Connectivity/service/src/com/android/server/connectivity/ClatCoordinator.java';owner=T/'packages/modules/Connectivity/service/src/com/android/server/BpfNetMaps.java';js=java.read_text();assert 'Actual userspace clatd; no unavailable BPF map/offload/cookie API.' in js and 'mGtaStats.tagClatSocket(writeSock6);' in js;assert 'ro.gta3xlwifi.legacy_networking' in owner.read_text()
oldjava=A/'clat-java-host-20261115-03/report.json';jr=json.loads(oldjava.read_text());assert jr['passed'];assert sha(java)==jr['inputs_sha256']['/srv/android/ports/lineage-24.0-arm64/clat-coordinator24-20261115-01/java/com/android/server/connectivity/ClatCoordinator.java']
prod=T/'out/target/product/gta3xlwifi';jni=prod/'apex/com.android.tethering/lib64/libservice-connectivity.so';daemon=prod/'system/bin/aconfigd-system';oldroot=A/'runtime20-ota-build-20261117-01/target-files.zip';files={}
with zipfile.ZipFile(a.archive) as z,zipfile.ZipFile(oldroot) as old:
 props=z.read('SYSTEM/build.prop').decode();assert 'ro.gta3xlwifi.legacy_networking=true' in props.splitlines() or any('ro.gta3xlwifi.legacy_networking=true' in z.read(n).decode().splitlines() for n in ['SYSTEM/product/etc/build.prop','SYSTEM/system_ext/etc/build.prop'])
 # APEX output is built by the target-files dependency graph; verify that the
 # packaged APEX is byte-identical to the installed APEX containing this JNI.
 apex=prod/'system/apex/com.android.tethering.capex';assert hashlib.sha256(z.read('SYSTEM/apex/com.android.tethering.capex')).hexdigest()==sha(apex)
 for name in ['SYSTEM/bin/aconfigd-system','SYSTEM/lib64/libaconfigd_rust.dylib.so']:
  if name not in z.namelist():continue
  data=z.read(name);h=hashlib.sha256(data).hexdigest()
  path=prod/'system'/name[len('SYSTEM/'):];assert h==sha(path)
  previous=hashlib.sha256(old.read(name)).hexdigest()
  if name.endswith('libaconfigd_rust.dylib.so'):assert h!=previous
  else:assert h==previous  # implementation is in the dynamically linked library
  files[name]=h
 assert 'SYSTEM/bin/aconfigd-system' in files
 with tempfile.TemporaryDirectory(prefix='clat-apex-',dir=a.output.parent) as td:
  tmp=Path(td)
  with zipfile.ZipFile(io.BytesIO(z.read('SYSTEM/apex/com.android.tethering.capex'))) as capex:
   with zipfile.ZipFile(io.BytesIO(capex.read('original_apex'))) as apexzip:
    image=tmp/'payload.img';image.write_bytes(apexzip.read('apex_payload.img'))
  dest=tmp/'jni.so';tool=T/'out/host/linux-x86/bin/debugfs_static'
  result=subprocess.run([str(tool),'-R','dump /lib64/libservice-connectivity.so '+str(dest),str(image)],capture_output=True,text=True,check=True)
  assert dest.exists() and sha(dest)==sha(jni),(result.stdout,result.stderr)

for f in [jni,daemon,prod/'system/lib64/libaconfigd_rust.dylib.so']:
 data=f.read_bytes();assert data.startswith(b'\x7fELF\x02\x01\x01')
needed=subprocess.run(['readelf','-d',str(daemon)],capture_output=True,text=True,check=True).stdout
assert 'Shared library: [libaconfigd_rust.dylib.so]' in needed
assert b'ro.gta3xlwifi.legacy_networking' in jni.read_bytes()
files['APEX/lib64/libservice-connectivity.so']=sha(jni)
assert 'clatd' in '\n'.join(p.name for p in (prod/'apex/com.android.tethering/bin/for-system').iterdir())
# Compare known failing physical BuildId, without publishing the private tombstone.
elf=subprocess.run(['readelf','-n',str(jni)],capture_output=True,text=True,check=True).stdout
assert '47de4be5bebe3135b31ddaef31404de2' not in elf and 'Build ID:' in elf
a.output.write_text(json.dumps(dict(passed=True,scope=__doc__,archive_sha256=g['archive_sha256'],actual_files_sha256=files,host_report_sha256=sha(proof),existing_Java_userspace_CLAT_regression_sha256=sha(oldjava),userspace_CLAT_source_sha256=sha(java),backend_owner_source_sha256=sha(owner),new_JNI_ELF_notes=elf.strip(),daemon_uses_rebuilt_shared_Rust_library=True,BPF_readiness_synthesized=False,hardware_boot_or_network_proven=False,flash_ready=False),indent=2)+'\n');print('PASS rebuilt JNI/flag daemon, genuine userspace selection and unchanged Java CLAT regression binding')
