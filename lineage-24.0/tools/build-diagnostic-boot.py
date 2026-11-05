#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Repack an isolated Samsung diagnostic boot image; never install or promote it."""
import argparse,hashlib,json,struct,subprocess,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','archive','kernel','output','source-audit']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();a.top=a.top.resolve();a.output=a.output.resolve();assert not a.output.is_relative_to(a.top) and not a.output.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(a.archive)=='5d6d30884abdf5c9cd2ea1680961005f681598a508bcb0937d6ebb27bebc3b45'
assert sha(a.kernel)=='5d3b21c1a9abb1e7c5175670606f9486c8a5da8f8ad536c132c5bd9c6c350fb2'
a.output.mkdir();(a.output/'NOT_READY_FOR_FLASHING.txt').write_text('DIAGNOSTIC PACKAGING ONLY. Strict policy/network/FBE/installer/ABI gates remain. No installation, recovery change or signing performed.\n')
with zipfile.ZipFile(a.archive) as z:original=z.read('IMAGES/boot.img')
assert hashlib.sha256(original).hexdigest()=='dea0c12a8fb5e748a26538b55a7a5d93594b799232cef616778f7867bea0a533'
trailer=b'SEANDROIDENFORCE';assert original.endswith(trailer)
base=a.output/'preserved-archive-boot.img';base.write_bytes(original)
unpack=a.top/'out/host/linux-x86/bin/unpack_bootimg';pack=a.top/'out/host/linux-x86/bin/mkbootimg'
result=subprocess.run([str(unpack),'--boot_img',str(base),'--out',str(a.output/'unpacked'),'--format','mkbootimg','-0'],capture_output=True,check=True)
args=[v.decode() for v in result.stdout.split(b'\0') if v];assert '--kernel' in args and '--header_version' in args
ki=args.index('--kernel')+1;kernel_original=Path(args[ki]);assert sha(kernel_original)=='33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553'
control=a.output/'control-raw.img';subprocess.run([str(pack),*args,'--output',str(control)],check=True);assert control.read_bytes()+trailer==original,'Official-tool byte-exact reconstruction failed'
newargs=list(args);newargs[ki]=str(a.kernel);raw=a.output/'candidate-raw.img';subprocess.run([str(pack),*newargs,'--output',str(raw)],check=True)
candidate=a.output/'NOT_FLASHABLE_boot.img';candidate.write_bytes(raw.read_bytes()+trailer)
def inspect(data):
 assert data[:8]==b'ANDROID!' and len(data)<33554432 and data.endswith(trailer)
 fields=struct.unpack_from('<10I',data,8);ks,ka,rs,ra,ss,sa,ta,page,hv,osword=fields
 assert page==2048 and hv==1 and rs==ss==0 and osword==570425770
 assert struct.unpack_from('<I',data,1632)[0]==0
 assert struct.unpack_from('<I',data,1644)[0]==1648
 assert data[48:64].rstrip(b'\0')==b'SRPSA25A005KU'
 cmd=data[64:576]+data[608:1632];assert b'androidboot.selinux=enforcing' in cmd
 kernel=data[page:page+ks];assert len(kernel)==ks and kernel[56:60]==b'ARMd'
 assert len(data)==page+((ks+page-1)//page)*page+len(trailer)
 return {'bytes':len(data),'kernel_size':ks,'kernel_address':ka,'ramdisk_size':rs,'ramdisk_address':ra,'second_size':ss,'second_address':sa,'tags_address':ta,'page_size':page,'header_version':hv,'os_version_word':osword,'kernel_sha256':hashlib.sha256(kernel).hexdigest(),'cmdline_sha256':hashlib.sha256(cmd).hexdigest(),'image_sha256':hashlib.sha256(data).hexdigest()}
x=inspect(original);y=inspect(candidate.read_bytes());assert y['kernel_sha256']==sha(a.kernel)
for k in x:
 if k not in ['bytes','kernel_size','kernel_sha256','image_sha256']:assert x[k]==y[k],k
check=a.top/'device/samsung/gta3xlwifi/check-ramdisk-size.py';subprocess.run(['python3',str(check),str(candidate)],check=True)
source=a.top/'system/tools/mkbootimg';device=a.top/'device/samsung/gta3xlwifi'
inputs=[a.archive,a.kernel,a.source_audit,unpack,pack,check,device/'mkbootimg.mk',device/'BoardConfig.mk',source/'mkbootimg.py',source/'unpack_bootimg.py',Path(__file__)]
report={'scope':'Official-tool byte-exact control reconstruction and isolated candidate geometry/header/input identity; NOT boot, encryption, hardware, ABI, installer or flash approval.','original':x,'candidate':y,'partition_bytes':33554432,'partition_margin_bytes':33554432-y['bytes'],'byte_exact_control_reconstruction_passed':True,'same_header_except_kernel_length_digest':True,'kernel_only_SAR_preserved':True,'Samsung_trailer_preserved':True,'signature_or_AVB_signing_performed':False,'android_prebuilt_or_targetfiles_modified':False,'recovery_or_vendor_modified':False,'source_revisions':{str(d):subprocess.check_output(['git','-C',str(d),'rev-parse','HEAD'],text=True).strip() for d in [source,device]},'inputs_sha256':{str(f):sha(f) for f in inputs},'pack_arguments':newargs,'flash_ready':False}
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'candidate_sha256':y['image_sha256'],'bytes':y['bytes'],'partition_margin_bytes':report['partition_margin_bytes'],'control_identical':True,'flash_ready':False},indent=2))
