#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile isolated combined UID policy transactions with all eight actual dependencies with the actual Android17 netd CFI command.

Object/architecture evidence only, not complete netd linking, kernel rule
execution, cross-family atomicity or network readiness. Every output is outside
TOP and no source/header/library or production object is replaced.
"""
import argparse,fcntl,hashlib,json,shlex,struct,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','snapshot','host-report','output']:p.add_argument('--'+n,type=Path,required=True)
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
 host=json.loads(a.host_report.read_text());assert host['passed'] and host['passed_cases']>=100 and host['stderr']=='';bind(a.host_report);bind(manifest);bind(Path(__file__))
 for name in ['Gta3xlwifiUidPolicy.cpp','Gta3xlwifiUidPolicy.h','Gta3xlwifiCheckedUidChains.cpp','Gta3xlwifiCheckedUidChains.h','Gta3xlwifiUidChainProgram.cpp','Gta3xlwifiUidChainProgram.h','Gta3xlwifiMeteredChainProgram.cpp','Gta3xlwifiMeteredChainProgram.h','Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiNetpolicyLease.h','Gta3xlwifiDualStackUidChains.cpp','Gta3xlwifiDualStackUidChains.h','Gta3xlwifiUidPolicyTransaction.cpp','Gta3xlwifiUidPolicyTransaction.h','Gta3xlwifiOrdinaryDispatch.cpp','Gta3xlwifiOrdinaryDispatch.h','linux/netfilter/gta3xlwifi_netpolicy.h']:
  values=[h for path,h in host['inputs_sha256'].items() if Path(path).name==Path(name).name];assert len(values)==1 and values[0]==sha(S/name);bind(S/name)
 target='out/soong/.intermediates/system/netd/server/libnetd_server/android_arm64_armv8-a_static_cfi/obj/system/netd/server/FirewallController.o';bind(T/target)
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);(O/'soong-command.txt').write_text(raw);assert len(raw.splitlines())==1
 cmd=shlex.split(raw)
 if cmd[0]=='PWD=/proc/self/cwd':cmd=cmd[1:]
 if Path(cmd[0]).name=='ccache':cmd=cmd[1:]
 assert '-c' in cmd and '-flto' in cmd and '-fsanitize=cfi' in cmd and cmd[-1]=='system/netd/server/FirewallController.cpp'
 bind(T/'system/netd/server/IptablesRestoreController.h')
 assert not (S/'IptablesRestoreController.h').exists()
 commands=[];objects=[]
 for source in ['Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiMeteredChainProgram','Gta3xlwifiNetpolicyLease','Gta3xlwifiDualStackUidChains','Gta3xlwifiUidPolicyTransaction','Gta3xlwifiOrdinaryDispatch']:
  command=cmd.copy();obj=O/(source+'.o');objects.append(str(obj))
  command[command.index('-o')+1]=str(obj);command[command.index('-MF')+1]=str(obj)+'.d';command[-1]=str(S/(source+'.cpp'));command.insert(1,'-I'+str(S));bind(T/command[0]);commands.append(command)
  r=subprocess.run(command,cwd=T,capture_output=True,text=True);(O/(source+'.compile.log')).write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr[-10000:]
 bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';link=[str(bin/'ld.lld'),'-r',*objects,'-o',str(O/'owner-dispatch-native.o')];r=subprocess.run(link,cwd=T,capture_output=True,text=True);(O/'link.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
 data=(O/'owner-dispatch-native.o').read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',data,16)==(1,183)
 symbols=subprocess.check_output([str(bin/'llvm-nm'),'--defined-only','--demangle',str(O/'owner-dispatch-native.o')],text=True)
 for name in ['::OrdinaryDispatch::append(','::UidPolicyTransaction::replace(','::UidPolicyTransaction::blockedReasons(','::DualStackUidChains::replace(','::NetpolicyLease::release(','::MeteredChainProgram::compile(','::UidPolicy::matchingUids(','::UidChainProgram::ordinary(','::CheckedUidChains::validateImage(','::CheckedUidChains::replace(']:assert name in symbols,name
 (O/'key-symbols.txt').write_text('\n'.join(line for line in symbols.splitlines() if any(x in line for x in ['UidPolicy::','CheckedUidChains::','UidChainProgram::','MeteredChainProgram::','UidPolicyTransaction::','NetpolicyLease::','DualStackUidChains::','OrdinaryDispatch::']))+'\n')
 for path in [ninja,bin/'ld.lld',bin/'llvm-nm']:bind(path)
 for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
 audit_source('source-audit-after.json')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'system_netd_revision':expected,'inputs_sha256':inputs,'compile_commands':commands,'link_command':link,'elf_class':64,'machine':183,'elf_type':1,'original_netd_cfi_flags_retained':True,'production_object_unchanged':True,'full_netd_linked':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual Android17 netd CFI flags compiled; native ARM64 object validated, production files unchanged')
finally:
 if not (O/'source-audit-after.json').exists():audit_source('source-audit-after.json')
