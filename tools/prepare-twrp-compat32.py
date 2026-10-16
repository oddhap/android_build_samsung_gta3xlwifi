#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage only the tested ARM32 runtime needed by Samsung's vendor crypto HALs.

Build the existing PIN-free ARM32 recovery from the same pinned TWRP sources
first. Its stripped libraries are inputs, never taken from the host or donor.
The ARM64 recovery and binder services remain native ARM64.
"""
import argparse,hashlib,json,shutil,struct,subprocess,tempfile,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runtime32',type=Path,required=True);p.add_argument('--vendor-root',type=Path,required=True);p.add_argument('--device',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
def sha(b):return hashlib.sha256(b).hexdigest()
def elf32(b):return b[:6]==b'\x7fELF\x01\x01' and struct.unpack_from('<H',b,18)[0]==40
staged={};visited=set();pending=[]
class VendorFiles:
 def read(self,name):return (a.vendor_root/name.removeprefix('VENDOR/')).read_bytes()
z=VendorFiles()
with tempfile.TemporaryDirectory() as temp:
 names={'VENDOR/'+p.relative_to(a.vendor_root).as_posix() for p in a.vendor_root.rglob('*') if p.is_file()}
 for rel in ['bin/mcDriverDaemon','bin/hw/android.hardware.keymaster@4.0-service','bin/hw/android.hardware.gatekeeper@1.0-service']:
  pending.append(('VENDOR/'+rel,z.read('VENDOR/'+rel)))
 # Modules loaded through hw_get_module/dlopen are absent from DT_NEEDED.
 for rel in ['lib/android.hardware.gatekeeper@1.0-impl.so','lib/hw/gatekeeper.exynos7904.so']:
  pending.append(('VENDOR/'+rel,z.read('VENDOR/'+rel)))
 # Bionic loads these dynamically; confirmed in the working ARM32 HAL maps.
 for library in ['libnetd_client.so','libdl_android.so']:
  source=a.runtime32/'system/lib'/library;content=source.read_bytes();assert elf32(content)
  staged['system/lib/'+library]=(source,content);pending.append(('system/lib/'+library,content))
 while pending:
  name,data=pending.pop()
  if name in visited:continue
  visited.add(name);assert elf32(data),name
  tempf=Path(temp)/'elf';tempf.write_bytes(data)
  import re
  needed=re.findall(r'Shared library: \[(.*?)\]',subprocess.check_output(['readelf','-d',str(tempf)],text=True))
  for library in needed:
   if any(x in names for x in ['VENDOR/lib/'+library,'VENDOR/lib/hw/'+library]):
    vendor=next(x for x in ['VENDOR/lib/'+library,'VENDOR/lib/hw/'+library] if x in names);pending.append((vendor,z.read(vendor)))
   else:
    source=a.runtime32/'system/lib'/library;assert source.is_file(),(name,library)
    content=source.read_bytes();assert elf32(content),str(source)
    staged['system/lib/'+library]=(source,content);pending.append(('system/lib/'+library,content))
 linker=a.runtime32/'system/bin/linker';content=linker.read_bytes();assert elf32(content)
 staged['system/bin/linker']=(linker,content)
for relative,(source,data) in staged.items():
 dest=a.device/'recovery/root'/relative;dest.parent.mkdir(parents=True,exist_ok=True)
 if dest.exists():assert dest.read_bytes()==data,'Refusing incompatible override: '+str(dest)
 else:shutil.copy2(source,dest)
report={'passed':True,'source':'source-built PIN-free TWRP ARM32 runtime from the existing pinned Android 12.1 checkout','vendor_crypto_elfs_checked':len([x for x in visited if x.startswith('VENDOR/')]),'compat32_files':{k:{'bytes':len(v[1]),'sha256':sha(v[1])} for k,v in sorted(staged.items())},'native_arm64_recovery_preserved':True}
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print('Staged '+str(len(staged))+' verified ARM32 runtime files for Samsung vendor crypto.')
