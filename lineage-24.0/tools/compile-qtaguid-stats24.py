#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile/link the complete staged Android17 libnetworkstats ARM64 CFI/APEX31.

Uses actual Soong commands and dependencies, redirects ALL outputs outside TOP.
No production source/output replacement, BPF readiness, kernel networking or
on-device accounting is established by this build.
"""
import argparse,hashlib,json,os,shlex,struct,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','staging','lock','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.staging.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);O.mkdir(parents=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
lock=json.loads(a.lock.read_text());project=T/lock['project'];native='service-t/native/libs/libnetworkstats';base=Path('out/soong/.intermediates')/lock['project']/native/'libnetworkstats';variant='android_arm64_armv8-a_static_cfi_apex31';srcdir=Path(lock['project'])/native
assert subprocess.check_output(['git','-C',str(project),'rev-parse','HEAD'],text=True).strip()==lock['revision']
inputs={str(a.lock.resolve()):sha(a.lock),str(Path(__file__).resolve()):sha(Path(__file__))}
for row in lock['files']:
 assert sha(S/row['path'])==row['candidate_sha256'];inputs[str(S/row['path'])]=row['candidate_sha256']
 actual=project/row['path']
 if row['before_sha256'] is None:assert not actual.exists()
 else:assert sha(actual)==row['before_sha256'];inputs[str(actual)]=sha(actual)
names=['BpfNetworkStats','NetworkTraceHandler','NetworkTracePoller'];objects=[base/variant/'obj'/srcdir/(n+'.o') for n in names];target=base/'android_arm64_armv8-a_shared_cfi_apex31/unstripped/libnetworkstats.so'
ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';graph='out/combined-lineage_gta3xlwifi.ninja'
raw=subprocess.check_output([str(ninja),'-f',graph,'-t','commands','-s',*[str(x) for x in objects],str(target)],cwd=T,text=True)
(O/'soong-commands.txt').write_text(raw);commands=raw.splitlines();assert len(commands)==4
built={};executed=[]
def run(cmd,label):
 assert all(not x.startswith('-oout/') for x in cmd)
 r=subprocess.run(cmd,cwd=T,capture_output=True,text=True);(O/(label+'.log')).write_text(r.stdout+r.stderr)
 executed.append({'label':label,'command':cmd,'returncode':r.returncode});assert r.returncode==0,r.stderr[-8000:]
for n in names+['Gta3xlwifiLegacyStats','QtaguidStats']:
 template=commands[names.index(n)] if n in names else commands[0];cmd=shlex.split(template)
 if cmd[0]=='PWD=/proc/self/cwd':cmd=cmd[1:]
 if Path(cmd[0]).name=='ccache':cmd=cmd[1:]
 assert '-c' in cmd and '-flto' in cmd and '-fsanitize=cfi' in cmd
 output=O/(n+'.o');dep=O/(n+'.o.d');cmd[cmd.index('-o')+1]=str(output);cmd[cmd.index('-MF')+1]=str(dep)
 source=S/native/(n+'.cpp') if n in ['BpfNetworkStats','Gta3xlwifiLegacyStats','QtaguidStats'] else project/native/(n+'.cpp')
 assert cmd[-1].endswith('.cpp');cmd[-1]=str(source);cmd.insert(1,'-I'+str(S/native))
 inputs[str(source)]=sha(source);run(cmd,n);built[n]=str(output)
link=shlex.split(commands[3]);rsp=next(x[1:] for x in link if x.startswith('@'));original_rsp=T/rsp;tokens=shlex.split(original_rsp.read_text());inputs[str(original_rsp)]=sha(original_rsp)
for obj,n in zip(objects,names):assert tokens.count(str(obj))==1;tokens[tokens.index(str(obj))]=built[n]
tokens[0:0]=[built[n] for n in ['Gta3xlwifiLegacyStats','QtaguidStats']]
for token in tokens:
 if token not in built.values() and not token.startswith('-'):
  path=T/token;assert path.is_file(),token;inputs[str(path)]=sha(path)
newrsp=O/'link.rsp';newrsp.write_text(shlex.join(tokens)+'\n');link[link.index('@'+rsp)]='@'+str(newrsp);binary=O/'libnetworkstats.so';link[link.index('-o')+1]=str(binary)
for flag in ['-Wl,--no-undefined','-Wl,--fatal-warnings','-fsanitize=cfi','-fsanitize-cfi-cross-dso']:assert flag in link
run(link,'link')
data=binary.read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH',data,16)==(3,183)
bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';readelf=bin/'llvm-readelf';nm=bin/'llvm-nm'
def symbols(path):
 text=subprocess.check_output([str(nm),'-D','--defined-only','--format=posix',str(path)],text=True)
 return {line.split()[0] for line in text.splitlines() if line.split()}
def dynamic(path):
 text=subprocess.check_output([str(readelf),'-d',str(path)],text=True)
 return [line.split('Shared library: ',1)[1] for line in text.splitlines() if '(NEEDED)' in line], [line.split('Library soname: ',1)[1] for line in text.splitlines() if '(SONAME)' in line]
baseline=T/target;old,new=symbols(baseline),symbols(binary);assert old<=new,sorted(old-new);assert '__cfi_check' in new
assert dynamic(baseline)==dynamic(binary);inputs[str(baseline)]=sha(baseline)
for path in [ninja,readelf,nm,Path(link[0]) if Path(link[0]).is_absolute() else T/link[0]]:inputs[str(path)]=sha(path)
for name,h in inputs.items():assert sha(Path(name))==h,'Input changed during compilation: '+name
report={'passed':True,'scope':__doc__,'source_lock':lock,'executed':executed,'inputs_sha256':inputs,'binary_sha256':sha(binary),'elf_class':64,'machine':183,'baseline_defined_dynamic_symbols_retained':len(old),'new_defined_dynamic_symbols':sorted(new-old),'dynamic_needed_and_soname_unchanged':True,'cfi_check_export_retained':True,'android32_built':False,'hardware_tested':False,'active_source_modified':False,'flash_ready':False}
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: complete real Android17 ARM64 CFI/APEX31 libnetworkstats linked; existing exports/SONAME/NEEDED retained')
