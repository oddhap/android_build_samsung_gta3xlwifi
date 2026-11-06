#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify actual init/vold output and both native keyutils architecture variants.

Build/link/source equivalence evidence only. No device keyring, encryption,
TEE operation, native interrupt, signing or flashing test is performed.
"""
import argparse,hashlib,json,struct,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','host-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
host=json.loads(a.host_report.read_text());assert host['passed'] and host['samsung_uapi_payload_layout_matches_android17'] and host['no_real_keyring_syscalls']
assert [x['stdout'].strip() for x in host['results']]==['passed_cases=32','passed_cases=56']
files=['system/vold/KeyUtil.cpp','system/core/init/init.cpp','system/core/libgta3xlwifi_keyutils/keyutils.cpp','system/core/libgta3xlwifi_keyutils/include/keyutils.h']
equivalent=[]
for name in files:
 candidates=[(path,h) for path,h in host['inputs_sha256'].items() if path.endswith('/'+name)];assert len(candidates)==1,(name,candidates)
 assert sha(T/name)==candidates[0][1],name
 equivalent.append({'path':name,'sha256':candidates[0][1]})
test_tools=[(path,h) for path,h in host['inputs_sha256'].items() if path.endswith('/test-legacy-fscrypt.py')];assert len(test_tools)==1
path,h=test_tools[0];assert sha(Path(path))==h
text=Path(path).read_text();assert "UBSAN_OPTIONS='halt_on_error=1'" in text and 'not result.stderr' in text
prod=T/'out/target/product/gta3xlwifi/system/bin';rows=[];inputs={str(a.host_report):sha(a.host_report)}
def elf(data,cls,machine):
 assert data[:7]==b'\x7fELF'+bytes([cls,1,1]);assert struct.unpack_from('<H',data,18)[0]==machine
 return {'elf_class':cls,'machine':machine,'type':struct.unpack_from('<H',data,16)[0]}
for name,keywords in [('init',[b'Legacy encrypted storage keyring setup failed']),('vold',[b'Cannot install an empty storage key',b'Failed to reclaim legacy encrypted inode caches'])]:
 path=prod/name;data=path.read_bytes();meta=elf(data,2,183);assert meta['type']==3
 for word in keywords:assert word in data,(name,word)
 inputs[str(path)]=sha(path);rows.append({'path':str(path),**meta,'sha256':sha(path),'legacy_profile_literals_present':[x.decode() for x in keywords]})
bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';linker=bin/'ld.lld';nm=bin/'llvm-nm';archives=[]
for variant,cls,machine in [('android_arm64_armv8-a_static',2,183),('android_arm_armv8-a_static',1,40)]:
 archive=T/'out/soong/.intermediates/system/core/libgta3xlwifi_keyutils/libgta3xlwifi_keyutils'/variant/'libgta3xlwifi_keyutils.a';before=sha(archive);obj=O/(variant+'.o')
 # LTO archives may contain LLVM bitcode, not ELF. Let the real Android linker
 # infer the input architecture; never force a target to make this check pass.
 cmd=[str(linker),'-r','--whole-archive',str(archive),'--no-whole-archive','-o',str(obj)]
 r=subprocess.run(cmd,capture_output=True,text=True);(O/(variant+'-link.log')).write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,r.stdout+r.stderr
 data=obj.read_bytes();meta=elf(data,cls,machine);assert meta['type']==1
 result=subprocess.check_output([str(nm),'--defined-only',str(obj)],text=True);(O/(variant+'-symbols.txt')).write_text(result)
 symbols={line.split()[-1] for line in result.splitlines() if line.split()};assert {'add_key','keyctl_get_keyring_ID','keyctl_search','keyctl_unlink'}<=symbols
 assert sha(archive)==before;inputs[str(archive)]=before
 archives.append({'archive':str(archive),'sha256':before,**meta,'defined_symbols':sorted(symbols),'link_command':cmd})
for name in [linker,nm,Path(__file__)]:inputs[str(name)]=sha(name)
report={'passed':True,'scope':__doc__,'binaries':rows,'architecture_checks':archives,'host_tested_sources_byte_identical':equivalent,'inputs_sha256':inputs,'hardware_tested':False,'actual_user_key_material_accessed':False,'flash_ready':False}
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: real init/vold legacy code linked, host-tested bodies match, actual keyutils ARM32/ARM64 variants validated')
