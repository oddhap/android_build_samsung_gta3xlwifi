#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib,json,subprocess,ctypes,stat
A=Path('/srv/android/artifacts/lineage-24.0-arm64');T=Path('/srv/android/src/lineage-24.0-arm64');O=A/'ion-compat-probe-20261117-02';O.mkdir(exist_ok=False)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=A/'ion-policy-baseline-20261117-01/report.json';r=json.loads(base.read_text());cmd=r['results'][0]['command'].copy();inputs=r['inputs'];assert all(sha(Path(x['path']))==x['sha256'] for x in inputs)
cil=O/'ion-compat.cil';cil.write_text(''.join('(allow '+s+' ion_device (chr_file (getattr open read ioctl lock map watch watch_reads)))\n' for s in ['hal_graphics_allocator_server','hal_graphics_composer_server','surfaceflinger']))
cmd[cmd.index('-o')+1]=str(O/'strict.policy');cmd.append(str(cil));assert '-N' not in cmd
p=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(p.stdout+p.stderr);assert p.returncode==0,p.stderr
r['inputs']=inputs+[{'path':str(cil),'sha256':sha(cil)}];r['results'][0].update(command=cmd,compiled_policy_sha256=sha(O/'strict.policy'));r['isolated_extra_device_rules']=True;(O/'report.json').write_text(json.dumps(r,indent=2)+'\n')
fc=T/'out/target/product/gta3xlwifi/system/etc/selinux/plat_file_contexts';new=O/'file_contexts';new.write_bytes(fc.read_bytes()+b'\n/dev/ion -c u:object_r:ion_device:s0\n')
lib=ctypes.CDLL('libselinux.so.1');lib.selabel_open.restype=ctypes.c_void_p;lib.selabel_lookup.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_char_p),ctypes.c_char_p,ctypes.c_int];lib.selabel_close.argtypes=[ctypes.c_void_p]
class Opt(ctypes.Structure):_fields_=[('type',ctypes.c_int),('value',ctypes.c_char_p)]
lib.selabel_open.argtypes=[ctypes.c_uint,ctypes.POINTER(Opt),ctypes.c_uint];out=[]
for f in [fc,new]:
 op=Opt(3,str(f).encode());handle=lib.selabel_open(0,ctypes.byref(op),1);assert handle
 for name,mode in [('/dev/ion',stat.S_IFCHR),('/dev/ion',stat.S_IFREG),('/dev/ion_other',stat.S_IFCHR),('/dev/ion/child',stat.S_IFCHR)]:
  ctx=ctypes.c_char_p();assert lib.selabel_lookup(handle,ctypes.byref(ctx),name.encode(),mode)==0
  label=ctx.value.decode();expected='u:object_r:ion_device:s0' if f==new and name=='/dev/ion' and mode==stat.S_IFCHR else 'u:object_r:device:s0';assert label==expected,(name,label,expected);out.append({'file':str(f),'path':name,'mode':mode,'label':label});lib.freecon(ctx)
 lib.selabel_close(handle)
(O/'label-lookups.json').write_text(json.dumps(out,indent=2)+'\n')
queries=[]
for s in ['hal_graphics_allocator_default','hal_graphics_composer_default','surfaceflinger']:
 for target in ['ion_device','device']:
  for perm in ['getattr','open','read','ioctl','map','write']:
   expected='observe' if target=='ion_device' and perm=='write' else ('allow' if target=='ion_device' else 'deny')
   queries.append(dict(source='u:r:'+s+':s0',target='u:object_r:'+target+':s0',**{'class':'chr_file'},permission=perm,expected=expected))
(O/'queries.json').write_text(json.dumps(queries,indent=2)+'\n');print('PASS strict ION candidate and eight precise file-context lookups')
