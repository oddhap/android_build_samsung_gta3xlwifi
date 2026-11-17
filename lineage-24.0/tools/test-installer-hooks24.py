#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual Android17 installer hooks and genuine packaged inputs offline.

Builds only an in-memory/script ZIP fixture; does not run Edify, touch a device
or claim that header identity proves FBE decryption.
"""
import argparse,hashlib,importlib.util,json,struct,sys,types,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','archive','source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sys.path.insert(0,str(a.top/'build/make/tools/releasetools'));sys.dont_write_bytecode=True
s=importlib.util.spec_from_file_location('selected_releasetools',a.source);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
sha=lambda b:hashlib.sha256(b).hexdigest()
class Script:
 def __init__(self):self.lines=[]
 def AppendExtra(self,line):self.lines.append(line)
class Override:
 def __init__(self,z,replacements):self.z=z;self.replacements=replacements
 def read(self,name):return self.replacements[name] if name in self.replacements else self.z.read(name)
results=[]
with zipfile.ZipFile(a.archive) as z:
 source=z.read('META/releasetools.py');assert source==a.source.read_bytes(),'Packaged hooks do not match selected source'
 helper=z.read('SYSTEM/bin/gta3xlwifi_recovery_header_sync')
 assert helper[:5]==b'\x7fELF\x01' and struct.unpack_from('<H',helper,18)[0]==40
 assert b'--preflight\x00' in helper and b'--apply\x00' not in helper
 with zipfile.ZipFile(O/'script-fixture.zip','w') as out:
  info=types.SimpleNamespace(input_zip=z,target_zip=None,output_zip=out,script=Script())
  m._begin(info);m._end(info);text='\n'.join(info.script.lines)+'\n';(O/'script.edify').write_text(text)
  assert text.count('"--preflight"')==2 and '--apply' not in text and 'unsupported' not in text
  assert 'vendor-unmounted-check.sh' in text and 'abort(' in text and 'write_raw_image' not in text and 'block_image_update' not in text
 with zipfile.ZipFile(O/'script-fixture.zip') as out:
  assert out.read('recovery-header-sync')==helper
  assert out.read('vendor-unmounted-check.sh')==m._VENDOR_MOUNT_GUARD
 results.append('actual packaged helper and source hooks produce two read-only guards')
 (O/'IMAGES').mkdir();(O/'IMAGES/vendor.img').write_bytes(z.read('IMAGES/vendor.img'))
 image=m._hybrid_vendor(z,str(O));assert image.blocksize*image.total_blocks==343932928;image.simg_f.close()
 results.append('actual packaged vendor accepted with exact digest and real sparse geometry')
 def reject(label,changes):
  info=types.SimpleNamespace(input_zip=Override(z,changes),target_zip=None)
  try:m._target(info)
  except (ValueError,KeyError):results.append(label);return
  raise AssertionError('Missing rejection: '+label)
 props=z.read('SYSTEM/build.prop');assert b'ro.build.version.release=17\n' in props
 reject('Android14 target rejected',{'SYSTEM/build.prop':props.replace(b'ro.build.version.release=17\n',b'ro.build.version.release=14\n')})
 boot=z.read('IMAGES/boot.img');tampered=bytearray(boot);tampered[2048]^=1
 reject('unreviewed kernel rejected',{'IMAGES/boot.img':bytes(tampered)})
 tampered=bytearray(boot);tampered[44]^=1
 reject('boot/build Keymaster metadata mismatch rejected',{'IMAGES/boot.img':bytes(tampered)})
 tampered=bytearray(helper);tampered[4]=2
 reject('wrong helper ABI rejected',{'SYSTEM/bin/gta3xlwifi_recovery_header_sync':bytes(tampered)})
 try:m._hybrid_vendor(Override(z,{'IMAGES/vendor.img':b'wrong vendor'}),str(O))
 except ValueError:results.append('unreviewed vendor rejected before image processing')
 else:raise AssertionError('Unreviewed vendor accepted')
report={'passed':True,'scope':__doc__,'selected_source_sha256':sha(a.source.read_bytes()),'packaged_helper_sha256':sha(helper),'cases':results,'device_touched':False,'Android17_FBE_validated':False,'flash_ready':False}
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(results),'actual package installer-hook cases')
