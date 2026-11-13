#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the actual modified BandwidthController with Android17 netd CFI flags.

Isolated object and partial link evidence only. Does not install/activate rules,
replace production objects, start a service or claim complete netd readiness.
"""
import argparse,fcntl,hashlib,json,shlex,struct,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','snapshot','host-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T) and not S.is_relative_to(T)
mutex=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(mutex,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(p):inputs[str(p.resolve())]=sha(p)
def audit(name):subprocess.run([sys.executable,str(Path(__file__).with_name('audit-port.py')),str(T),str(a.snapshot),str(O/name)],check=True)
bind(Path(__file__));bind(Path(__file__).with_name('audit-port.py'));bind(a.host_report);audit('source-before.json')
try:
 r=json.loads(a.host_report.read_text());assert r['passed'] and r['mark_variants']==20 and r['stock_factory_and_other_controller_source_unchanged'] and r['passed_cases']>=1000
 for p in [S/'BandwidthController.cpp',S/'BandwidthController.h',T/'system/netd/server/BandwidthController.cpp',T/'system/netd/server/BandwidthController.h']:
  assert r['inputs_sha256'][str(p)]==sha(p);bind(p)
 manifest=a.snapshot/'port-manifest.xml';bind(manifest);expected=next(p.get('revision') for p in ET.parse(manifest).getroot().iter('project') if p.get('path',p.get('name'))=='system/netd');assert subprocess.check_output(['git','-C',str(T/'system/netd'),'rev-parse','HEAD'],text=True).strip()==expected;assert not subprocess.check_output(['git','-C',str(T/'system/netd'),'status','--porcelain'])
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';bind(ninja);target='out/soong/.intermediates/system/netd/server/libnetd_server/android_arm64_armv8-a_static_cfi/obj/system/netd/server/BandwidthController.o';bind(T/target)
 raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);assert len(raw.splitlines())==1;(O/'soong-command.txt').write_text(raw);cmd=shlex.split(raw)
 if cmd[0]=='PWD=/proc/self/cwd':cmd=cmd[1:]
 if Path(cmd[0]).name=='ccache':cmd=cmd[1:]
 assert '-flto' in cmd and '-fsanitize=cfi' in cmd and cmd[-1]=='system/netd/server/BandwidthController.cpp';bind(T/cmd[0]);cmd[cmd.index('-o')+1]=str(O/'BandwidthController.o');cmd[cmd.index('-MF')+1]=str(O/'BandwidthController.o.d');cmd[-1]=str(S/'BandwidthController.cpp');cmd.insert(1,'-I'+str(S))
 x=subprocess.run(cmd,cwd=T,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-10000:]
 bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';link=[str(bin/'ld.lld'),'-r',str(O/'BandwidthController.o'),'-o',str(O/'bandwidth-factory-native.o')];bind(bin/'ld.lld');bind(bin/'llvm-nm');x=subprocess.run(link,cwd=T,capture_output=True,text=True);(O/'link.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.stdout,x.stderr)
 data=(O/'bandwidth-factory-native.o').read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',data,16)==(1,183)
 syms=subprocess.check_output([str(bin/'llvm-nm'),'--defined-only','--demangle',str(O/'bandwidth-factory-native.o')],text=True)
 for name in ['BandwidthController::makeGta3xlwifiAccountingCommands()','BandwidthController::enableBandwidthControl()','BandwidthController::enableDataSaver(bool)','BandwidthController::setInterfaceQuota(']:assert name in syms,name
 (O/'key-symbols.txt').write_text('\n'.join(line for line in syms.splitlines() if 'BandwidthController::' in line)+'\n')
 for p,h in inputs.items():assert sha(Path(p))==h
 audit('source-after.json');(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'system_netd_revision':expected,'inputs_sha256':inputs,'compile_command':cmd,'link_command':link,'elf_class':64,'machine':183,'original_netd_cfi_flags_retained':True,'production_object_unchanged':True,'full_netd_linked':False,'rules_installed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual full BandwidthController compiled with A17 ARM64 CFI and partially linked; stock source/object unchanged')
finally:
 if not (O/'source-after.json').exists():audit('source-after.json')
