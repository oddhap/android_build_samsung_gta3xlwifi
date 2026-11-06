#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile lease source with the pinned Samsung kernel's actual GCC command.

C/object preflight only, not complete Kbuild, recordmcount processing, kernel
linking, packet execution or network readiness. All outputs remain isolated.
"""
import argparse,fcntl,hashlib,json,shlex,struct,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['parent','source','host-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();P=a.parent.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(P);mutex=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(mutex,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
inputs={}
def bind(p):inputs[str(p.resolve())]=sha(p)
host=json.loads(a.host_report.read_text());assert host['passed'] and host['passed_cases']==44 and host['stderr']==''
source=S/'net/netfilter/gta3xlwifi_netpolicy.c';header=S/'include/uapi/linux/netfilter/gta3xlwifi_netpolicy.h'
for path in [source,header]:assert host['inputs_sha256'][str(path)]==sha(path);bind(path)
config=P/'out/.config';image=P/'out/arch/arm64/boot/Image';assert sha(config)=='fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea';assert sha(image)=='9fc9c3cf0d46d6f62e810a1b598a6bf0c6a0465ca923fa953bd6eed318270d92'
command_file=P/'out/net/netfilter/.xt_qtaguid.o.cmd';line=command_file.read_text().splitlines()[0];assert line.startswith('cmd_net/netfilter/xt_qtaguid.o := ');raw=line.split(' := ',1)[1];args=shlex.split(raw)
if ';' in args:args=args[:args.index(';')]
assert Path(args[0]).name=='aarch64-linux-android-gcc' and '-c' in args
original_source=next(x for x in args if x.endswith('/net/netfilter/xt_qtaguid.c'));args[args.index(original_source)]=str(source)
args[args.index('-o')+1]=str(O/'gta3xlwifi_netpolicy.o')
assert sum(x.startswith('-Wp,-MD,') for x in args)==1
for i,x in enumerate(args):
 if x.startswith('-Wp,-MD,'):args[i]='-Wp,-MD,'+str(O/'gta3xlwifi_netpolicy.d')
 if x.startswith('-DKBUILD_BASENAME='):args[i]='-DKBUILD_BASENAME="gta3xlwifi_netpolicy"'
 if x.startswith('-DKBUILD_MODNAME='):args[i]='-DKBUILD_MODNAME="gta3xlwifi_netpolicy"'
args.insert(1,'-I'+str(S/'include/uapi'))
for path in [a.host_report,Path(__file__),config,image,command_file,Path(original_source),P/'out/net/netfilter/xt_qtaguid.o',Path(args[0]),P/'src/include/linux/miscdevice.h',P/'src/include/linux/netfilter/x_tables.h',P/'src/fs/open.c']:bind(path)
r=subprocess.run(args,cwd=P/'out',capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
obj=O/'gta3xlwifi_netpolicy.o';data=obj.read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',data,16)==(1,183)
nm=Path(str(args[0]).removesuffix('gcc')+'nm');symbols=subprocess.check_output([str(nm),'--defined-only',str(obj)],text=True);(O/'symbols.txt').write_text(symbols)
for name in ['netpolicy_ioctl','netpolicy_open','netpolicy_flush','netpolicy_release','netpolicy_match']:assert name in symbols,name
bind(nm)
for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'inputs_sha256':inputs,'command':args,'elf_class':64,'machine':183,'elf_type':1,'object_sha256':sha(obj),'actual_parent_kernel_headers_and_config_used':True,'parent_image_source_output_unchanged':True,'full_kernel_linked':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual Samsung GCC4.9/config/headers compile lease object as ARM64; parent Image/output unchanged')
