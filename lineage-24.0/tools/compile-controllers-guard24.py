#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the isolated guarded Controllers source and complete actual Android17 netd.

Uses original CFI compile/link commands, all original archive objects except the
one rebuilt source, and full source audits. Does not execute netd or rules, wire
the legacy backend, replace production outputs or claim runtime readiness.
"""
import argparse,fcntl,hashlib,json,re,shlex,struct,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','snapshot','host-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
mutex=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(mutex,fcntl.LOCK_EX|fcntl.LOCK_NB)
O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
def run(cmd,log=None):
 r=subprocess.run(list(map(str,cmd)),cwd=T,capture_output=True,text=True)
 if log:(O/log).write_text(r.stdout+r.stderr)
 assert r.returncode==0,(cmd,r.returncode,r.stdout[-1000:],r.stderr[-8000:])
 return r.stdout
audit=Path(__file__).with_name('audit-port.py');bind(audit);bind(Path(__file__))
def source_audit(name):run([sys.executable,audit,T,a.snapshot,O/name])
source_audit('source-audit-before.json')
try:
 host=json.loads(a.host_report.read_text());assert host['passed'] and host['passed_cases']==960 and host['stderr']=='';bind(a.host_report)
 candidate=S/'Controllers.cpp';original=T/'system/netd/server/Controllers.cpp'
 for path in [candidate,original]:assert host['inputs_sha256'][str(path)]==sha(path);bind(path)
 assert not (S/'Controllers.h').exists();bind(T/'system/netd/server/Controllers.h')
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';bind(ninja)
 def query(mode,target):return run([ninja,'-f','out/combined-lineage_gta3xlwifi.ninja','-t',mode,*(['-s'] if mode=='commands' else []),target])
 root='out/soong/.intermediates/system/netd/server/libnetd_server/android_arm64_armv8-a_static_cfi/'
 archive=root+'libnetd_server.a';bind(T/archive);q=query('query',archive);(O/'archive-query.txt').write_text(q)
 objects=re.findall(r'^    (\S+\.o)$',q,re.M);assert len(objects)==18 and len(objects)==len(set(objects))
 bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';bind(bin/'llvm-ar')
 members_before=run([bin/'llvm-ar','t',T/archive]).splitlines();assert members_before==[Path(x).name for x in objects]
 target=next(x for x in objects if x.endswith('/system/netd/server/Controllers.o'))
 raw=query('commands',target);(O/'soong-command.txt').write_text(raw);assert len(raw.splitlines())==1
 cmd=shlex.split(raw)
 if cmd[0]=='PWD=/proc/self/cwd':cmd=cmd[1:]
 if Path(cmd[0]).name=='ccache':cmd=cmd[1:]
 assert '-c' in cmd and '-flto' in cmd and '-fsanitize=cfi' in cmd and cmd[-1]=='system/netd/server/Controllers.cpp'
 cmd[cmd.index('-o')+1]=str(O/'Controllers.o');cmd[cmd.index('-MF')+1]=str(O/'Controllers.o.d');cmd[-1]=str(candidate);bind(T/cmd[0]);run(cmd,'compile.log')
 bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';candidate_archive=O/'libnetd_server.a'
 for x in objects:bind(T/x)
 members=[str(O/'Controllers.o') if x==target else x for x in objects]
 run([bin/'llvm-ar','crsD',candidate_archive,*members],'archive.log');bind(bin/'llvm-ar')
 target='out/soong/.intermediates/system/netd/server/netd/android_arm64_armv8-a_cfi/unstripped/netd';bind(T/target)
 raw=query('commands',target);(O/'link-command-original.txt').write_text(raw);assert len(raw.splitlines())==1
 link=shlex.split(raw);expanded=[]
 for x in link:
  if x.startswith('@'):bind(T/x[1:]);expanded+=shlex.split((T/x[1:]).read_text())
  else:expanded.append(x)
 assert expanded.count(archive)==1
 expanded[expanded.index(archive)]=str(candidate_archive);expanded[expanded.index('-o')+1]=str(O/'netd')
 for x in expanded:
  if x not in [str(O/'netd'),str(candidate_archive)] and (T/x).is_file():bind(T/x)
 run(expanded,'link.log')
 data=(O/'netd').read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',data,16)==(3,183)
 for value in [b'-A %s -m gta3xlwifi_guard -j DROP\n\0',b'ro.gta3xlwifi.legacy_networking\0']:assert value in data,value
 readelf=bin/'llvm-readelf';bind(readelf)
 def needed(path):return re.findall(r'\(NEEDED\).*\[(.*?)\]',run([readelf,'-d',path]))
 deps=needed(O/'netd');assert deps==needed(T/target)
 for path,h in inputs.items():assert sha(Path(path))==h,'Changed input: '+path
 source_audit('source-audit-after.json')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'inputs_sha256':inputs,'compile_command':cmd,'link_command':expanded,'original_archive_members_verified_exactly':True,'original_archive_object_count':len(objects),'rebuilt_original_objects':1,'elf_class':64,'machine':183,'elf_type':3,'needed':deps,'original_cfi_flags_retained':True,'full_netd_linked':True,'netd_or_rules_executed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual full Android17 netd CFI binary linked with isolated guarded Controllers; production inputs and source unchanged')
finally:
 if not (O/'source-audit-after.json').exists():source_audit('source-audit-after.json')
