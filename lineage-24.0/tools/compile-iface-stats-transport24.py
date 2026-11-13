#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile isolated interface-counter reader and shared-lease policy projection with the actual Android17 netd CFI command.

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
 host=json.loads(a.host_report.read_text());assert host['passed'] and host['passed_cases']>=900 and host['hard_no_firewall_after_first_image_set'] and host['one_lease_four_state_publication'] and host['stderr']=='';bind(a.host_report);bind(manifest);bind(Path(__file__))
 for name in ['Gta3xlwifiCheckedUidChains.cpp','Gta3xlwifiCheckedUidChains.h','Gta3xlwifiUidPolicy.cpp','Gta3xlwifiUidPolicy.h','Gta3xlwifiUidChainProgram.cpp','Gta3xlwifiUidChainProgram.h','Gta3xlwifiOrdinaryDispatch.cpp','Gta3xlwifiOrdinaryDispatch.h','Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiNetpolicyLease.h','Gta3xlwifiSocketRoots.cpp','Gta3xlwifiSocketRoots.h','Gta3xlwifiIngressPolicy.cpp','Gta3xlwifiIngressPolicy.h','Gta3xlwifiMeteredChainProgram.cpp','Gta3xlwifiMeteredChainProgram.h','Gta3xlwifiMeteredRoots.cpp','Gta3xlwifiMeteredRoots.h','Gta3xlwifiLocalNetworkState.cpp','Gta3xlwifiLocalNetworkState.h','Gta3xlwifiUidPermissionState.cpp','Gta3xlwifiUidPermissionState.h','Gta3xlwifiSocketPolicyProjection.cpp','Gta3xlwifiSocketPolicyProjection.h','projection-guards.inc',*[str(p.relative_to(S)) for p in (S/'linux/netfilter').glob('*.h')]]:
  values=[h for path,h in host['inputs_sha256'].items() if Path(path).name==Path(name).name];assert len(values)==1 and values[0]==sha(S/name);bind(S/name)
 kernel_header=a.kernel/'include/net/gta3xlwifi_socket_tables.h';assert '#define GTA3XLWIFI_SOCKET_TABLE "g24sock"' in kernel_header.read_text();bind(kernel_header)
 for header in (S/'linux/netfilter').glob('*.h'):
  actual=a.kernel/'include/uapi/linux/netfilter'/header.name
  assert header.read_bytes()==actual.read_bytes();bind(actual)
 target='out/soong/.intermediates/system/netd/server/libnetd_server/android_arm64_armv8-a_static_cfi/obj/system/netd/server/FirewallController.o';bind(T/target)
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);(O/'soong-command.txt').write_text(raw);assert len(raw.splitlines())==1
 cmd=shlex.split(raw)
 if cmd[0]=='PWD=/proc/self/cwd':cmd=cmd[1:]
 if Path(cmd[0]).name=='ccache':cmd=cmd[1:]
 assert '-c' in cmd and '-flto' in cmd and '-fsanitize=cfi' in cmd and cmd[-1]=='system/netd/server/FirewallController.cpp'
 bind(T/'system/netd/server/IptablesRestoreController.h')
 assert not (S/'IptablesRestoreController.h').exists()
 commands=[];objects=[]
 for source in ['Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiNetpolicyLease','Gta3xlwifiSocketRoots','Gta3xlwifiIngressPolicy','Gta3xlwifiMeteredChainProgram','Gta3xlwifiMeteredRoots','Gta3xlwifiLocalNetworkState','Gta3xlwifiUidPermissionState','Gta3xlwifiSocketPolicyProjection']:
  command=cmd.copy();obj=O/(source+'.o');objects.append(str(obj))
  command[command.index('-o')+1]=str(obj);command[command.index('-MF')+1]=str(obj)+'.d';command[-1]=str(S/(source+'.cpp'));command.insert(1,'-I'+str(S));bind(T/command[0]);commands.append(command)
  r=subprocess.run(command,cwd=T,capture_output=True,text=True);(O/(source+'.compile.log')).write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr[-10000:]
 bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';link=[str(bin/'ld.lld'),'-r',*objects,'-o',str(O/'socket-projection-native.o')];r=subprocess.run(link,cwd=T,capture_output=True,text=True);(O/'link.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
 data=(O/'socket-projection-native.o').read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',data,16)==(1,183)
 symbols=subprocess.check_output([str(bin/'llvm-nm'),'--defined-only','--demangle',str(O/'socket-projection-native.o')],text=True)
 for name in ['::CheckedUidChains::replace(','::CheckedUidChains::read(','::CheckedUidChains::validTableNames(','::CheckedUidChains::validTableImage(','::UidChainProgram::ordinary(','::OrdinaryDispatch::append(','::NetpolicyLease::requireSocketTables(','::SocketRoots::prepare(','::SocketRoots::activate(','::SocketRoots::verify(','::IngressPolicy::compile(','::NetpolicyLease::requireIngressMatches(','::MeteredRoots::prepare(','::MeteredRoots::activate(','::MeteredRoots::verify(','::MeteredChainProgram::compile(','::SocketPolicyProjection::start(','::SocketPolicyProjection::replace(','::SocketPolicyProjection::snapshot(','::SocketPolicyProjection::removeUid(','::NetpolicyLease::requirePolicyPrimitives(','::NetpolicyLease::readIfaceStats(','::SocketPolicyProjection::readIfaceStats(']:assert name in symbols,name
 (O/'key-symbols.txt').write_text('\n'.join(line for line in symbols.splitlines() if any(x in line for x in ['CheckedUidChains::','UidChainProgram::','OrdinaryDispatch::','SocketRoots::','NetpolicyLease::','IngressPolicy::','MeteredRoots::','MeteredChainProgram::','SocketPolicyProjection::']))+'\n')
 wire=O/'uid-wire.cpp';wire.write_text('#include <linux/netfilter/gta3xlwifi_iface_stats.h>\nstatic_assert(sizeof(gta3xlwifi_iface_stats_match)==8);\nstatic_assert(sizeof(gta3xlwifi_iface_stats_entry)==40);\nstatic_assert(sizeof(gta3xlwifi_iface_stats_transfer)==32);\nstatic_assert(__builtin_offsetof(gta3xlwifi_iface_stats_entry,rx_packets)==8);\nstatic_assert(__builtin_offsetof(gta3xlwifi_iface_stats_entry,tx_bytes)==32);\nstatic_assert(__builtin_offsetof(gta3xlwifi_iface_stats_transfer,entries)==8);\nstatic_assert(__builtin_offsetof(gta3xlwifi_iface_stats_transfer,lost_updates)==16);\nstatic_assert(__builtin_offsetof(gta3xlwifi_iface_stats_transfer,update_sequence)==24);\nstatic_assert(GTA3XLWIFI_IFACE_STATS_GET==0xc020675a);\nextern "C" unsigned iface_wire_size(){return sizeof(gta3xlwifi_iface_stats_transfer);}\n');bind(wire);wire_results=[]
 for variant,cls,machine in [('android_arm64_armv8-a_static',2,183),('android_arm_armv8-a_static',1,40)]:
  obj='out/soong/.intermediates/system/core/libgta3xlwifi_keyutils/libgta3xlwifi_keyutils/'+variant+'/obj/system/core/libgta3xlwifi_keyutils/keyutils.o';bind(T/obj)
  raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',obj],cwd=T,text=True);assert len(raw.splitlines())==1
  (O/(variant+'-soong-command.txt')).write_text(raw);args=shlex.split(raw)
  if args[0]=='PWD=/proc/self/cwd':args=args[1:]
  if Path(args[0]).name=='ccache':args=args[1:]
  assert args[-1]=='system/core/libgta3xlwifi_keyutils/keyutils.cpp' and '-c' in args
  args[args.index('-o')+1]=str(O/(variant+'.o'));args[args.index('-MF')+1]=str(O/(variant+'.o.d'));args[-1]=str(wire);args.insert(1,'-I'+str(S));bind(T/args[0])
  x=subprocess.run(args,cwd=T,capture_output=True,text=True);(O/(variant+'-compile.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
  wire_link=[str(bin/'ld.lld'),'-r',str(O/(variant+'.o')),'-o',str(O/(variant+'-native.o'))];x=subprocess.run(wire_link,cwd=T,capture_output=True,text=True);assert x.returncode==0 and not x.stderr,(x.stdout,x.stderr)
  data=(O/(variant+'-native.o')).read_bytes();assert data[:7]==b'\x7fELF'+bytes([cls,1,1]) and struct.unpack_from('<HH',data,16)==(1,machine)
  wire_results.append({'variant':variant,'elf_class':32 if cls==1 else 64,'machine':machine,'compile_command':args,'link_command':wire_link,'iface_transfer_bytes':32,'iface_entry_bytes':40,'iface_get_command':0xc020675a})
 for path in [ninja,bin/'ld.lld',bin/'llvm-nm']:bind(path)
 for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
 audit_source('source-audit-after.json')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'system_netd_revision':expected,'inputs_sha256':inputs,'compile_commands':commands,'link_command':link,'elf_class':64,'machine':183,'elf_type':1,'wire_layout_actual_multilib':wire_results,'original_netd_cfi_flags_retained':True,'production_object_unchanged':True,'full_netd_linked':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual Android17 netd CFI flags compiled; native ARM64 object validated, production files unchanged')
finally:
 if not (O/'source-audit-after.json').exists():audit_source('source-audit-after.json')
