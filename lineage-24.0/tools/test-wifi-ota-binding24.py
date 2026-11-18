#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual old/new OTA vendor guards against the actual reviewed image."""
from pathlib import Path
import hashlib,importlib.util,json,subprocess,sys,zipfile
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');C=A/'wifi-ota-binding-composition-20261118-01';O=A/'wifi-ota-binding-host-20261118-01';O.mkdir(exist_ok=False)
sys.dont_write_bytecode=True;sys.path.insert(0,str(T/'build/make/tools/releasetools'));rel='device/samsung/gta3xlwifi/releasetools.py';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
old=load('old_binding',C/'baseline'/rel);new=load('new_binding',C/'files'/rel);archive=O/'vendor-fixture.zip';v=A/'wifi-supplicant-vendor-20261118-02/report.json';r=json.loads(v.read_text());assert r['passed'];assert new._VENDOR_SHA256==r['vendor_sparse_sha256'] and new._VENDOR_BYTES==old._VENDOR_BYTES==343932928
with zipfile.ZipFile(archive,'w') as fixture:fixture.write(A/'wifi-supplicant-vendor-20261118-02/vendor.img','IMAGES/vendor.img')
with zipfile.ZipFile(archive) as z:
 data=z.read('IMAGES/vendor.img');assert hashlib.sha256(data).hexdigest()==r['vendor_sparse_sha256'];(O/'IMAGES').mkdir();(O/'IMAGES/vendor.img').write_bytes(data)
 try:old._hybrid_vendor(z,str(O))
 except ValueError as e:assert str(e)=='Hybrid vendor differs from the reviewed image'
 else:raise AssertionError('Original stale binding unexpectedly accepted new image')
 image=new._hybrid_vendor(z,str(O));assert image.blocksize*image.total_blocks==343932928;image.simg_f.close()
 class Corrupt:
  def read(self,name):
   assert name=='IMAGES/vendor.img';b=bytearray(data);b[-1]^=1;return bytes(b)
 try:new._hybrid_vendor(Corrupt(),str(O))
 except ValueError as e:assert str(e)=='Hybrid vendor differs from the reviewed image'
 else:raise AssertionError('Tampered vendor accepted')
report=dict(passed=True,scope=__doc__,stale_binding_failure_reproduced=True,reviewed_vendor_accepted=True,actual_AOSP_sparse_geometry_validated=True,tampered_vendor_rejected_before_image_processing=True,guard_retained=True,source_sha256={rel:sha(C/'files'/rel)},baseline_sha256=sha(C/'baseline'/rel),vendor_report_sha256=sha(v),hardware_tested=False,flash_ready=False);(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS actual stale-hash reproduction, authorized vendor acceptance, sparse geometry and tampered vendor rejection')
