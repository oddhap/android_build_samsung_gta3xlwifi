#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile isolated UID image/leased packet-barrier I/O with the actual Android17 netd CFI command.

Object/architecture evidence only, not complete netd linking, kernel rule
execution, cross-family atomicity or network readiness. Every output is outside
TOP and no source/header/library or production object is replaced.
"""
import argparse,fcntl,hashlib,json,shlex,struct,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','snapshot','host-report','kernel','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
# Kati rewrites mmap'ed Ninja inputs. Even a read-only -t query can SIGBUS
# during that generation; acquire the same lock used by all build/source jobs.
mutex=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a')
fcntl.flock(mutex,fcntl.LOCK_EX|fcntl.LOCK_NB)
O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(p):inputs[str(p.resolve())]=sha(p)
audit=Path(__file__).with_name('audit-port.py');bind(audit)
def audit_source(name):subprocess.run([sys.executable,str(audit),str(T),str(a.snapshot),str(O/name)],check=True)
audit_source('source-audit-before.json')
try:
 manifest=a.snapshot/'port-manifest.xml';expected=next(x.get('revision') for x in ET.parse(manifest).getroot().iter('project') if x.get('path',x.get('name'))=='system/netd');assert subprocess.check_output(['git','-C',str(T/'system/netd'),'rev-parse','HEAD'],text=True).strip()==expected;assert not subprocess.check_output(['git','-C',str(T/'system/netd'),'status','--porcelain'])
 host=json.loads(a.host_report.read_text());assert host['passed'] and host['passed_cases']==90 and host['stderr']=='';bind(a.host_report);bind(manifest);bind(Path(__file__))
 for name in ['Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiNetpolicyLease.h','linux/netfilter/gta3xlwifi_netpolicy.h','linux/netfilter/gta3xlwifi_uid_permissions.h']:
  values=[h for path,h in host['inputs_sha256'].items() if Path(path).name==Path(name).name];assert len(values)==1 and values[0]==sha(S/name);bind(S/name)
 header=S/'linux/netfilter/gta3xlwifi_netpolicy.h';kernel_header=a.kernel/'include/uapi/linux/netfilter/gta3xlwifi_netpolicy.h';assert header.read_bytes()==kernel_header.read_bytes();bind(kernel_header)
 new_header=S/'linux/netfilter/gta3xlwifi_uid_permissions.h';kernel_new=a.kernel/'include/uapi/linux/netfilter/gta3xlwifi_uid_permissions.h';assert new_header.read_bytes()==kernel_new.read_bytes();bind(kernel_new)
 target='out/soong/.intermediates/system/netd/server/libnetd_server/android_arm64_armv8-a_static_cfi/obj/system/netd/server/FirewallController.o';bind(T/target)
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);(O/'soong-command.txt').write_text(raw);assert len(raw.splitlines())==1
 cmd=shlex.split(raw)
 if cmd[0]=='PWD=/proc/self/cwd':cmd=cmd[1:]
 if Path(cmd[0]).name=='ccache':cmd=cmd[1:]
 assert '-c' in cmd and '-flto' in cmd and '-fsanitize=cfi' in cmd and cmd[-1]=='system/netd/server/FirewallController.cpp'
 cmd[cmd.index('-o')+1]=str(O/'netpolicy-lease.o');cmd[cmd.index('-MF')+1]=str(O/'netpolicy-lease.o.d');cmd[-1]=str(S/'Gta3xlwifiNetpolicyLease.cpp');cmd.insert(1,'-I'+str(S));bind(T/cmd[0]);r=subprocess.run(cmd,cwd=T,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr[-10000:]
 bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';link=[str(bin/'ld.lld'),'-r',str(O/'netpolicy-lease.o'),'-o',str(O/'netpolicy-lease-native.o')];r=subprocess.run(link,cwd=T,capture_output=True,text=True);(O/'link.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
 data=(O/'netpolicy-lease-native.o').read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',data,16)==(1,183)
 symbols=subprocess.check_output([str(bin/'llvm-nm'),'--defined-only','--demangle',str(O/'netpolicy-lease-native.o')],text=True)
 for name in ['::NetpolicyLease::start(','::NetpolicyLease::hold(','::NetpolicyLease::release(','::NetpolicyLease::isHeld(','::NetpolicyLease::stop(','::NetpolicyLease::readUidPermissions(','::NetpolicyLease::replaceUidPermissions(']:assert name in symbols,name
 (O/'key-symbols.txt').write_text('\n'.join(line for line in symbols.splitlines() if 'NetpolicyLease::' in line)+'\n')

 wire=O/'uid-wire.cpp';wire.write_text('#include <linux/netfilter/gta3xlwifi_uid_permissions.h>\nstatic_assert(sizeof(gta3xlwifi_uid_permission_transfer)==24);\nstatic_assert(__builtin_offsetof(gta3xlwifi_uid_permission_transfer,revision)==8);\nstatic_assert(__builtin_offsetof(gta3xlwifi_uid_permission_transfer,entries)==16);\nstatic_assert(sizeof(gta3xlwifi_uid_permission_entry)==8);\nstatic_assert(GTA3XLWIFI_UID_FEATURES==0x6754);\nstatic_assert(GTA3XLWIFI_UID_SET_IMAGE==0x40186755);\nstatic_assert(GTA3XLWIFI_UID_GET_IMAGE==0xc0186756);\nextern "C" unsigned uid_wire_size(){return sizeof(gta3xlwifi_uid_permission_transfer);}\n');bind(wire);wire_results=[]
 for variant,cls,machine in [('android_arm64_armv8-a_static',2,183),('android_arm_armv8-a_static',1,40)]:
  obj='out/soong/.intermediates/system/core/libgta3xlwifi_keyutils/libgta3xlwifi_keyutils/'+variant+'/obj/system/core/libgta3xlwifi_keyutils/keyutils.o';bind(T/obj)
  raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',obj],cwd=T,text=True);assert len(raw.splitlines())==1
  (O/(variant+'-soong-command.txt')).write_text(raw);args=shlex.split(raw)
  if args[0]=='PWD=/proc/self/cwd':args=args[1:]
  if Path(args[0]).name=='ccache':args=args[1:]
  assert args[-1]=='system/core/libgta3xlwifi_keyutils/keyutils.cpp' and '-c' in args
  args[args.index('-o')+1]=str(O/(variant+'.o'));args[args.index('-MF')+1]=str(O/(variant+'.o.d'));args[-1]=str(wire);args.insert(1,'-I'+str(S));bind(T/args[0])
  x=subprocess.run(args,cwd=T,capture_output=True,text=True);(O/(variant+'-compile.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
  link=[str(bin/'ld.lld'),'-r',str(O/(variant+'.o')),'-o',str(O/(variant+'-native.o'))];x=subprocess.run(link,cwd=T,capture_output=True,text=True);assert x.returncode==0 and not x.stderr,(x.stdout,x.stderr)
  data=(O/(variant+'-native.o')).read_bytes();assert data[:7]==b'\x7fELF'+bytes([cls,1,1]) and struct.unpack_from('<HH',data,16)==(1,machine)
  wire_results.append({'variant':variant,'elf_class':32 if cls==1 else 64,'machine':machine,'compile_command':args,'link_command':link,'transfer_bytes':24,'entry_bytes':8,'set_command':0x40186755,'get_command':0xc0186756})
 for path in [ninja,bin/'ld.lld',bin/'llvm-nm']:bind(path)
 for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'system_netd_revision':expected,'inputs_sha256':inputs,'compile_command':cmd,'link_command':link,'elf_class':64,'machine':183,'elf_type':1,'private_uapi_matches_actual_kernel':True,'original_netd_cfi_flags_retained':True,'production_object_unchanged':True,'wire_layout_actual_multilib':wire_results,'full_netd_linked':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual Android17 netd CFI flags compiled; native ARM64 object validated, production files unchanged')
finally:
 audit_source('source-audit-after.json')
