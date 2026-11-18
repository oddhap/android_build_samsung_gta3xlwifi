#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check actual built ION context resolution and unchanged trusted HAL memberships."""
from pathlib import Path
import ctypes,hashlib,json,stat,sys
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');O=Path(sys.argv[1]);assert not O.exists();O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
R=A/'ion-ui-policy-strict-20261117-01';r=json.loads((R/'strict/report.json').read_text());assert r['passed_strict']
for attr,typ in [('hal_graphics_allocator_server','hal_graphics_allocator_default'),('hal_graphics_composer_server','hal_graphics_composer_default')]:
 rows=[line for item in r['inputs'] for line in Path(item['path']).read_text().splitlines() if line.startswith('(typeattributeset '+attr+' ')];assert rows==['(typeattributeset '+attr+' ('+typ+'))'],rows
prod=T/'out/target/product/gta3xlwifi';paths=[prod/'system/etc/selinux/plat_file_contexts',prod/'system/system_ext/etc/selinux/system_ext_file_contexts',prod/'product/etc/selinux/product_file_contexts',R/'metadata/vendor/etc/selinux/vendor_file_contexts'];inputs={str(f):sha(f) for f in paths};combined=O/'combined_file_contexts';combined.write_text('\n'.join(f.read_text() for f in paths)+'\n')
lib=ctypes.CDLL('libselinux.so.1');lib.selabel_open.restype=ctypes.c_void_p
class Opt(ctypes.Structure):_fields_=[('type',ctypes.c_int),('value',ctypes.c_char_p)]
lib.selabel_open.argtypes=[ctypes.c_uint,ctypes.POINTER(Opt),ctypes.c_uint];lib.selabel_lookup.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_char_p),ctypes.c_char_p,ctypes.c_int];lib.selabel_close.argtypes=[ctypes.c_void_p];lib.freecon.argtypes=[ctypes.c_char_p]
opt=Opt(3,str(combined).encode());handle=lib.selabel_open(0,ctypes.byref(opt),1);assert handle;results=[]
for name,mode in [('/dev/ion',stat.S_IFCHR),('/dev/ion',stat.S_IFREG),('/dev/ion_other',stat.S_IFCHR),('/dev/ion/child',stat.S_IFCHR)]:
 ctx=ctypes.c_char_p();assert lib.selabel_lookup(handle,ctypes.byref(ctx),name.encode(),mode)==0;label=ctx.value.decode();expected='u:object_r:ion_device:s0' if name=='/dev/ion' and mode==stat.S_IFCHR else 'u:object_r:device:s0';assert label==expected,(name,label,expected);results.append(dict(path=name,mode=mode,label=label));lib.freecon(ctx)
lib.selabel_close(handle)
(O/'report.json').write_text(json.dumps(dict(passed=True,scope=__doc__,inputs_sha256=inputs,strict_report_sha256=sha(R/'strict/report.json'),actual_lookups=results,HAL_server_memberships_exact=True,hardware_tested=False),indent=2)+'\n');print('PASS actual combined context lookup and exact HAL server memberships')
