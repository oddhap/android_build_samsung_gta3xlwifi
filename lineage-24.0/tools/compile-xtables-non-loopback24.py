#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build all six isolated builtin legacy netfilter xtables extensions with actual Android17 commands.

Rebuilds the real extension registry, complete libext archive and native iptables
binary outside TOP. Does not execute iptables or install rules. This establishes
registration/build/link contracts, not kernel packet behavior or readiness.
"""
import argparse,fcntl,hashlib,json,re,shlex,struct,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','kernel','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();K=a.kernel.resolve();O=a.output.resolve()
assert not O.exists() and not O.is_relative_to(T) and not S.is_relative_to(T)
mutex=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(mutex,fcntl.LOCK_EX|fcntl.LOCK_NB)
O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(p):
 p=Path(p).resolve();inputs[str(p)]=sha(p)
def run(cmd,log=None):
 r=subprocess.run(list(map(str,cmd)),cwd=T,capture_output=True,text=True)
 if log:(O/log).write_text(r.stdout+r.stderr)
 assert r.returncode==0,(cmd,r.returncode,r.stdout[-1000:],r.stderr[-6000:])
 return r.stdout
# Every original project and reviewed patch must match before and after.
audit=Path(__file__).with_name('audit-port.py');bind(audit);bind(Path(__file__))
def source_audit(name):run([sys.executable,audit,T,a.snapshot,O/name])
source_audit('source-audit-before.json')
try:
 I=T/'external/iptables';header=S/'include/linux/netfilter/gta3xlwifi_netpolicy.h';kernel_header=K/'include/uapi/linux/netfilter/gta3xlwifi_netpolicy.h';source=S/'extensions/libxt_gta3xlwifi_guard.c'
 assert header.read_bytes()==kernel_header.read_bytes()
 appid_source=S/'extensions/libxt_gta3xlwifi_appid.c';appid_header=S/'include/linux/netfilter/gta3xlwifi_appid.h';appid_kernel=K/'include/uapi/linux/netfilter/gta3xlwifi_appid.h';assert appid_header.read_bytes()==appid_kernel.read_bytes()
 for x in [appid_source,appid_header,appid_kernel]:bind(x)
 raw_header=S/'include/linux/netfilter/gta3xlwifi_socket_uid.h';raw_kernel=K/'include/uapi/linux/netfilter/gta3xlwifi_socket_uid.h';assert raw_header.read_bytes()==raw_kernel.read_bytes();bind(raw_header);bind(raw_kernel)
 raw_sources=[S/'extensions'/('libxt_gta3xlwifi_'+n+'.c') for n in ['raw_uid','raw_appid','owner_skip','non_loopback']]
 skip_header=S/'include/linux/netfilter/gta3xlwifi_owner_skip.h';skip_kernel=K/'include/uapi/linux/netfilter/gta3xlwifi_owner_skip.h';assert skip_header.read_bytes()==skip_kernel.read_bytes();bind(skip_header);bind(skip_kernel)
 for x in raw_sources:bind(x)
 for x in [header,kernel_header,source,I/'extensions/Android.bp',I/'extensions/filter_init',I/'extensions/gen_init',a.snapshot/'port-manifest.xml',a.snapshot/'source-lock.json']:bind(x)
 bp=(I/'extensions/Android.bp').read_text();assert 'srcs: ["libxt_*.c"]' in bp and '"libxt_gta3xlwifi_guard.c"' not in bp
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';bind(ninja)
 def query(mode,target):return run([ninja,'-f','out/combined-lineage_gta3xlwifi.ninja','-t',mode,*(['-s'] if mode=='commands' else []),target])
 root='out/soong/.intermediates/external/iptables/extensions/libext/android_arm64_armv8-a_static/'
 archive=root+'libext.a';bind(T/archive)
 q=query('query',archive);(O/'archive-query.txt').write_text(q)
 objects=re.findall(r'^    (\S+\.o)$',q,re.M);assert len(objects)>50 and len(objects)==len(set(objects))
 init=next(x for x in objects if x.endswith('/initext.o'));example=next(x for x in objects if x.endswith('/libxt_comment.o'))
 commands=[]
 def compile_like(target,src,dest):
  raw=query('commands',target);assert len(raw.splitlines())==1
  cmd=shlex.split(raw)
  if cmd[0]=='PWD=/proc/self/cwd':cmd=cmd[1:]
  if Path(cmd[0]).name=='ccache':cmd=cmd[1:]
  assert '-c' in cmd and '-target' in cmd and cmd[cmd.index('-target')+1].startswith('aarch64-')
  old=[i for i,x in enumerate(cmd) if x.endswith('.c')];assert len(old)==1
  bind(T/cmd[old[0]]);cmd[old[0]]=str(src);cmd[cmd.index('-o')+1]=str(dest)
  if '-MF' in cmd:cmd[cmd.index('-MF')+1]=str(dest)+'.d'
  cmd.insert(1,'-I'+str(S/'include'));bind(T/cmd[0]);commands.append(cmd)
  run(cmd,dest.name+'.log');return dest
 filtered=run(['sh',I/'extensions/filter_init',source]);assert 'void libxt_gta3xlwifi_guard_init(void)' in filtered and 'void _init(void)' not in filtered
 (O/'libxt_gta3xlwifi_guard.c').write_text(filtered)
 appid_filtered=run(['sh',I/'extensions/filter_init',appid_source]);assert 'void libxt_gta3xlwifi_appid_init(void)' in appid_filtered and 'void _init(void)' not in appid_filtered
 (O/'libxt_gta3xlwifi_appid.c').write_text(appid_filtered)
 for src in raw_sources:
  filtered_raw=run(['sh',I/'extensions/filter_init',src]);assert 'void '+src.stem+'_init(void)' in filtered_raw and 'void _init(void)' not in filtered_raw;(O/src.name).write_text(filtered_raw)
 # Reproduce the old generated registry exactly before adding one new entry.
 raw=query('commands',init);parts=shlex.split(raw);generated=next(x for x in parts if x.endswith('/initext.c'));old=(T/generated).read_text();bind(T/generated)
 names=re.findall(r'^void (libxt_\w+)_init\(void\);$',old,re.M);assert len(names)>50 and len(names)==len(set(names))
 old_sources=[I/'extensions'/(n+'.c') for n in names]
 assert run(['bash',I/'extensions/gen_init','',*old_sources])==old
 new=run(['bash',I/'extensions/gen_init','',*old_sources,source,appid_source,*raw_sources]);assert new.count('void libxt_gta3xlwifi_guard_init(void);')==1 and new.count('  libxt_gta3xlwifi_guard_init();')==1
 assert new.count('void libxt_gta3xlwifi_appid_init(void);')==1 and new.count('  libxt_gta3xlwifi_appid_init();')==1
 for src in raw_sources:assert new.count('void '+src.stem+'_init(void);')==1 and new.count('  '+src.stem+'_init();')==1
 (O/'initext.c').write_text(new)
 guard_obj=compile_like(example,O/'libxt_gta3xlwifi_guard.c',O/'libxt_gta3xlwifi_guard.o')
 appid_obj=compile_like(example,O/'libxt_gta3xlwifi_appid.c',O/'libxt_gta3xlwifi_appid.o')
 raw_objects=[compile_like(example,O/src.name,O/(src.stem+'.o')) for src in raw_sources]
 init_obj=compile_like(init,O/'initext.c',O/'initext.o')
 bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin'
 members=[str(init_obj) if x==init else x for x in objects]+[str(guard_obj),str(appid_obj),*map(str,raw_objects)]
 for x in objects:bind(T/x)
 candidate_archive=O/'libext.a';run([bin/'llvm-ar','crsD',candidate_archive,*members],'archive.log');bind(bin/'llvm-ar')
 def symbols(path):return run([bin/'llvm-nm','--defined-only',path])
 before=symbols(T/archive);after=symbols(candidate_archive)
 # All prior public registration functions and the new builtin must be defined.
 old_regs=set(re.findall(r'\bT (libxt_\w+_init|init_extensions)\b',before));new_regs=set(re.findall(r'\bT (libxt_\w+_init|init_extensions)\b',after))
 assert len(old_regs)>50 and new_regs==old_regs|{'libxt_gta3xlwifi_guard_init','libxt_gta3xlwifi_appid_init','libxt_gta3xlwifi_raw_uid_init','libxt_gta3xlwifi_raw_appid_init','libxt_gta3xlwifi_owner_skip_init','libxt_gta3xlwifi_non_loopback_init'}
 (O/'registration-symbols.txt').write_text('\n'.join(sorted(new_regs))+'\n')
 target='out/soong/.intermediates/external/iptables/iptables/iptables/android_arm64_armv8-a/unstripped/iptables';bind(T/target)
 link=shlex.split(query('commands',target));expanded=[]
 for x in link:
  if x.startswith('@'):
   bind(T/x[1:]);expanded+=shlex.split((T/x[1:]).read_text())
  else:expanded.append(x)
 assert expanded.count(archive)==1
 expanded[expanded.index(archive)]=str(candidate_archive);expanded[expanded.index('-o')+1]=str(O/'iptables')
 for x in expanded:
  if x not in [str(O/'iptables'),str(candidate_archive)] and (T/x).is_file():bind(T/x)
 commands.append(expanded);run(expanded,'link.log')
 data=(O/'iptables').read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',data,16)==(3,183)
 readelf=bin/'llvm-readelf';bind(readelf);bind(bin/'llvm-nm')
 def dynamic(path):return re.findall(r'\(NEEDED\).*\[(.*?)\]',run([readelf,'-d',path]))
 deps=dynamic(O/'iptables');assert deps==dynamic(T/target)
 final=symbols(O/'iptables')
 # ThinLTO inlines the small registration function. Verify the actual final
 # machine code passes the surviving guard structure to the registry instead.
 assert re.search(r'\bd guard_match(?:\.llvm\.\d+)?$',final,re.M)
 for callback in ['guard_init','guard_help','guard_print','appid_help','appid_print','appid_save','raw_uid_help','raw_uid_print','raw_uid_save','raw_appid_help','raw_appid_print','raw_appid_save','owner_skip_help','owner_skip_print','non_loopback_help','non_loopback_print']:assert re.search(r'\bt '+callback+r'$',final,re.M)
 objdump=bin/'llvm-objdump';bind(objdump)
 disasm=run([objdump,'-d','--disassemble-symbols=init_extensions',O/'iptables']);(O/'registration-disassembly.txt').write_text(disasm)
 for label in ['guard_match','appid_match','raw_uid_match','raw_appid_match','owner_skip_match','non_loopback_match']:
  assert re.search(r'adr\s+x0, 0x[0-9a-f]+ <'+label+r'(?:\.llvm\.\d+)?>\n(?:[^\n]*ldp[^\n]*\n)?[^\n]*\t(?:bl|b)\s+0x[0-9a-f]+ <xtables_register_match>',disasm),disasm[-1600:]

 for path,h in inputs.items():assert sha(Path(path))==h,'Changed input: '+path
 source_audit('source-audit-after.json')
 report={'passed':True,'scope':__doc__,'inputs_sha256':inputs,'commands':commands,'archive_original_registration_count':len(old_regs),'new_registration_count':len(new_regs),'elf_class':64,'machine':183,'elf_type':3,'needed':deps,'actual_registry_generator_used':True,'original_registry_reproduced_exactly':True,'final_machine_code_registers_all_six_private_matches':True,'full_native_iptables_linked':True,'rules_installed':False,'hardware_tested':False,'flash_ready':False}
 (O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: all six actual Android17 builtin registrations, complete archive and ARM64 iptables link; original inputs unchanged')
finally:
 if not (O/'source-audit-after.json').exists():source_audit('source-audit-after.json')
