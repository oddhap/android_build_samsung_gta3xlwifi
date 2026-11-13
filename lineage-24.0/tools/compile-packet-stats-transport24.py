#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile actual packet-store transport, accounting bootstrap and shared policy owner with Android17 CFI with the actual Android17 netd CFI command.

Object/architecture evidence only, not complete netd linking, kernel rule
execution, cross-family atomicity or network readiness. Every output is outside
TOP and no source/header/library or production object is replaced.
"""
import argparse,fcntl,hashlib,json,shlex,struct,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','snapshot','host-report','factory-report','regression-report','transport-report','kernel','output']:p.add_argument('--'+n,type=Path,required=True)
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
 regression=json.loads(a.regression_report.read_text());assert regression['passed'] and regression['passed_cases']>=994;bind(a.regression_report)
 transport=json.loads(a.transport_report.read_text());assert transport['passed'] and transport['passed_cases']>=99 and transport['stderr']=='';bind(a.transport_report)
 for name in ['Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiNetpolicyLease.h','linux/netfilter/gta3xlwifi_packet_stats.h']:
  values=[h for path,h in transport['inputs_sha256'].items() if Path(path).name==Path(name).name];assert values==[sha(S/name)];bind(S/name)
 factory=json.loads(a.factory_report.read_text());assert factory['passed'] and factory['mark_variants']==20 and factory['stock_factory_and_other_controller_source_unchanged'];bind(a.factory_report)
 for name in ['BandwidthController.cpp','BandwidthController.h']:
  hashes=[h for path,h in factory['inputs_sha256'].items() if path.endswith('/bandwidth-factory24-20261113-01/'+name)];assert hashes==[sha(S/name)];bind(S/name)
 for name in ['Gta3xlwifiCheckedUidChains.cpp','Gta3xlwifiCheckedUidChains.h','Gta3xlwifiUidPolicy.cpp','Gta3xlwifiUidPolicy.h','Gta3xlwifiUidChainProgram.cpp','Gta3xlwifiUidChainProgram.h','Gta3xlwifiOrdinaryDispatch.cpp','Gta3xlwifiOrdinaryDispatch.h','Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiNetpolicyLease.h','Gta3xlwifiSocketRoots.cpp','Gta3xlwifiSocketRoots.h','Gta3xlwifiIngressPolicy.cpp','Gta3xlwifiIngressPolicy.h','Gta3xlwifiMeteredChainProgram.cpp','Gta3xlwifiMeteredChainProgram.h','Gta3xlwifiMeteredRoots.cpp','Gta3xlwifiMeteredRoots.h','Gta3xlwifiLocalNetworkState.cpp','Gta3xlwifiLocalNetworkState.h','Gta3xlwifiUidPermissionState.cpp','Gta3xlwifiUidPermissionState.h','Gta3xlwifiSocketPolicyProjection.cpp','Gta3xlwifiSocketPolicyProjection.h','projection-guards.inc','Gta3xlwifiAccountingRoots.cpp','Gta3xlwifiAccountingRoots.h',*[str(p.relative_to(S)) for p in (S/'linux/netfilter').glob('*.h')]]:
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
 for source in ['Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiNetpolicyLease','Gta3xlwifiSocketRoots','Gta3xlwifiIngressPolicy','Gta3xlwifiMeteredChainProgram','Gta3xlwifiMeteredRoots','Gta3xlwifiLocalNetworkState','Gta3xlwifiUidPermissionState','Gta3xlwifiSocketPolicyProjection','Gta3xlwifiAccountingRoots','BandwidthController']:
  template=cmd
  if source=='BandwidthController':
   bwtarget=target.replace('FirewallController.o','BandwidthController.o');bind(T/bwtarget)
   bwraw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',bwtarget],cwd=T,text=True);assert len(bwraw.splitlines())==1;(O/'bandwidth-soong-command.txt').write_text(bwraw);template=shlex.split(bwraw)
   if template[0]=='PWD=/proc/self/cwd':template=template[1:]
   if Path(template[0]).name=='ccache':template=template[1:]
   assert '-flto' in template and '-fsanitize=cfi' in template and template[-1]=='system/netd/server/BandwidthController.cpp'
  command=template.copy();obj=O/(source+'.o');objects.append(str(obj))
  command[command.index('-o')+1]=str(obj);command[command.index('-MF')+1]=str(obj)+'.d';command[-1]=str(S/(source+'.cpp'));command.insert(1,'-I'+str(S));bind(T/command[0]);commands.append(command)
  r=subprocess.run(command,cwd=T,capture_output=True,text=True);(O/(source+'.compile.log')).write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr[-10000:]
 bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';link=[str(bin/'ld.lld'),'-r',*objects,'-o',str(O/'accounting-projection-native.o')];r=subprocess.run(link,cwd=T,capture_output=True,text=True);(O/'link.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
 data=(O/'accounting-projection-native.o').read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',data,16)==(1,183)
 symbols=subprocess.check_output([str(bin/'llvm-nm'),'--defined-only','--demangle',str(O/'accounting-projection-native.o')],text=True)
 for name in ['::CheckedUidChains::replace(','::CheckedUidChains::read(','::CheckedUidChains::validTableNames(','::CheckedUidChains::validTableImage(','::UidChainProgram::ordinary(','::OrdinaryDispatch::append(','::NetpolicyLease::requireSocketTables(','::SocketRoots::prepare(','::SocketRoots::activate(','::SocketRoots::verify(','::IngressPolicy::compile(','::NetpolicyLease::requireIngressMatches(','::MeteredRoots::prepare(','::MeteredRoots::activate(','::MeteredRoots::verify(','::MeteredChainProgram::compile(','::AccountingRoots::prepare(','::AccountingRoots::verifyProducers(','::SocketPolicyProjection::startWithAccounting(','BandwidthController::makeGta3xlwifiAccountingCommands()','::SocketPolicyProjection::start(','::SocketPolicyProjection::replace(','::SocketPolicyProjection::snapshot(','::SocketPolicyProjection::removeUid(','::NetpolicyLease::requirePolicyPrimitives(','::NetpolicyLease::requireIfaceAccountingPrimitives(','::NetpolicyLease::readPacketState(','::NetpolicyLease::readFrozenPacketStats(','::NetpolicyLease::readAppStats(','::NetpolicyLease::swapPacketStats(','::NetpolicyLease::acknowledgePacketStats(','::NetpolicyLease::setPacketCounterset(','::NetpolicyLease::deleteUidPacketStats(','::NetpolicyLease::readIfaceStats(','::SocketPolicyProjection::readIfaceStats(']:assert name in symbols,name
 (O/'key-symbols.txt').write_text('\n'.join(line for line in symbols.splitlines() if any(x in line for x in ['CheckedUidChains::','UidChainProgram::','OrdinaryDispatch::','SocketRoots::','NetpolicyLease::','IngressPolicy::','MeteredRoots::','MeteredChainProgram::','SocketPolicyProjection::']))+'\n')
 undefined=subprocess.check_output([str(bin/'llvm-nm'),'--undefined-only','--demangle',str(O/'accounting-projection-native.o')],text=True);private=[line for line in undefined.splitlines() if 'android::net::gta3xlwifi::' in line];assert not private,private
 (O/'namespace-link-report.json').write_text(json.dumps({'passed':True,'partial_object_sha256':sha(O/'accounting-projection-native.o'),'undefined_private_namespace_symbols':private,'scope':'Private namespace resolution only; platform/library/full service linking remains.'},indent=2)+'\n')
 wire=O/'uid-wire.cpp';wire.write_text('#include <linux/netfilter/gta3xlwifi_packet_stats.h>\nstatic_assert(sizeof(gta3xlwifi_stats_key)==16);\nstatic_assert(sizeof(gta3xlwifi_packet_stats_entry)==48);\nstatic_assert(sizeof(gta3xlwifi_app_stats_entry)==40);\nstatic_assert(sizeof(gta3xlwifi_packet_stats_state)==88);\nstatic_assert(sizeof(gta3xlwifi_packet_stats_transfer)==48);\nstatic_assert(sizeof(gta3xlwifi_packet_stats_swap)==32);\nstatic_assert(sizeof(gta3xlwifi_packet_stats_ack)==24);\nstatic_assert(sizeof(gta3xlwifi_packet_stats_edit)==24);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_entry,rx_packets)==16);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_entry,tx_bytes)==40);\nstatic_assert(__builtin_offsetof(gta3xlwifi_app_stats_entry,rx_packets)==8);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_state,active_epoch)==8);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_state,bank_epoch)==32);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_state,total_stats_lost)==72);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_transfer,epoch)==8);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_transfer,entries)==24);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_transfer,sequence)==40);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_swap,inactive_epoch)==24);\nstatic_assert(__builtin_offsetof(gta3xlwifi_packet_stats_ack,epoch)==8);\nstatic_assert(GTA3XLWIFI_STATS_GET_STATE==0x8058675b);\nstatic_assert(GTA3XLWIFI_STATS_READ==0xc030675c);\nstatic_assert(GTA3XLWIFI_STATS_SWAP==0xc020675d);\nstatic_assert(GTA3XLWIFI_STATS_ACK==0x4018675e);\nstatic_assert(GTA3XLWIFI_STATS_EDIT==0x4018675f);\nextern "C" unsigned packet_stats_wire_size(){return sizeof(gta3xlwifi_packet_stats_transfer);}\n');bind(wire);wire_results=[]
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
  wire_results.append({'variant':variant,'elf_class':32 if cls==1 else 64,'machine':machine,'compile_command':args,'link_command':wire_link,'packet_transfer_bytes':48,'packet_entry_bytes':48,'app_entry_bytes':40,'state_bytes':88,'swap_bytes':32,'ack_bytes':24,'edit_bytes':24,'ioctl_commands':[0x8058675b,0xc030675c,0xc020675d,0x4018675e,0x4018675f]})
 for path in [ninja,bin/'ld.lld',bin/'llvm-nm']:bind(path)
 for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
 audit_source('source-audit-after.json')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'system_netd_revision':expected,'inputs_sha256':inputs,'compile_commands':commands,'link_command':link,'elf_class':64,'machine':183,'elf_type':1,'wire_layout_actual_multilib':wire_results,'original_netd_cfi_flags_retained':True,'production_object_unchanged':True,'full_netd_linked':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual Android17 netd CFI flags compiled; native ARM64 object validated, production files unchanged')
finally:
 if not (O/'source-audit-after.json').exists():audit_source('source-audit-after.json')
