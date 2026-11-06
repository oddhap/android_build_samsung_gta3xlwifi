#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify actual integrated qtaguid module/JAR outputs and source-test identities.

Confirms actual installed expanded-APEX ARM64 library and compiled ARM32 static
archive. Not a packaged APEX, native counter, Android regression, network-ready
or flash-ready validation. Never accesses live counters or user data.
"""
import argparse,hashlib,json,struct,subprocess,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','native-reference','native-lock','java-lock','adapter-report','parser-report','output']:p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--expected-adapter-cases',type=int,choices=[20,37],default=20)
p.add_argument('--device-lock',type=Path)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);O.mkdir(parents=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
inputs={}
def bind(p):inputs[str(p.resolve())]=sha(p)
for p in [a.native_reference,a.native_lock,a.java_lock,a.adapter_report,a.parser_report,Path(__file__)]:bind(p)
locks=[json.loads(p.read_text()) for p in [a.native_lock,a.java_lock]];project=T/locks[0]['project'];assert all(x['project']=='packages/modules/Connectivity' and x['revision']=='7c04d866538e6f689823b769fb5c1e614ca0e295' for x in locks)
assert subprocess.check_output(['git','-C',str(project),'rev-parse','HEAD'],text=True).strip()==locks[0]['revision']
for lock in locks:
 for row in lock['files']:assert sha(project/row['path'])==row['candidate_sha256'];bind(project/row['path'])
adapter=json.loads(a.adapter_report.read_text());parser=json.loads(a.parser_report.read_text());assert adapter['passed'] and adapter['passed_cases']==a.expected_adapter_cases and adapter['stderr']=='';assert parser['passed'] and parser['passed_cases']==36 and parser['fatal_ubsan'] and parser['stderr']==''
native='service-t/native/libs/libnetworkstats'
for report,names in [(adapter,['Gta3xlwifiLegacyStats.cpp','Gta3xlwifiLegacyStats.h','QtaguidStats.cpp','QtaguidStats.h']),(parser,['QtaguidStats.cpp','QtaguidStats.h'])]:
 for name in names:
  hashes=[h for path,h in report['inputs_sha256'].items() if Path(path).name==name];assert len(hashes)==1 and sha(project/native/name)==hashes[0]
for path,h in parser['inputs_sha256'].items():
 if Path(path).name=='xt_qtaguid.c':assert sha(Path(path))==h;bind(Path(path))
if a.expected_adapter_cases==37:
 assert a.device_lock is not None
 device=json.loads(a.device_lock.read_text());bind(a.device_lock);root=T/'device/samsung/gta3xlwifi'
 assert subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()==device['new_revision']
 source=root/device['changed_path'];installed_rc=T/'out/target/product/gta3xlwifi/product/etc/init/init.gta3xlwifi.compat.rc'
 assert sha(source)==device['candidate_sha256'] and sha(installed_rc)==device['candidate_sha256'];bind(source);bind(installed_rc)
 for name in ['test-qtaguid-adapter24.py','android_filesystem_config.h','xt_qtaguid.c']:
  rows=[(Path(path),h) for path,h in adapter['inputs_sha256'].items() if Path(path).name==name];assert len(rows)==1 and sha(rows[0][0])==rows[0][1];bind(rows[0][0])
base=T/'out/soong/.intermediates/packages/modules/Connectivity'/native/'libnetworkstats';variant=base/'android_arm64_armv8-a_shared_cfi_apex31';shared=variant/'unstripped/libnetworkstats.so';stripped=variant/'libnetworkstats.so';installed=T/'out/target/product/gta3xlwifi/apex/com.android.tethering/lib64/libnetworkstats.so';reference=a.native_reference.parent/'libnetworkstats.so';r=json.loads(a.native_reference.read_text());assert r['passed'] and sha(reference)==r['binary_sha256'];assert sha(installed)==sha(stripped)
def elf(p,cls,machine,kind):
 data=p.read_bytes();assert data[:7]==b'\x7fELF'+bytes([cls,1,1]);assert struct.unpack_from('<HH',data,16)==(kind,machine)
 return data
for path in [shared,stripped,installed,reference]:
 data=elf(path,2,183,3);assert b'/proc/net/xt_qtaguid/stats' in data and b'/proc/net/xt_qtaguid/iface_stat_fmt' in data;bind(path)
bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';nm=bin/'llvm-nm';readelf=bin/'llvm-readelf';linker=bin/'ld.lld'
def symbols(p):return {x.split()[0] for x in subprocess.check_output([str(nm),'-D','--defined-only','--format=posix',str(p)],text=True).splitlines() if x.split()}
current=symbols(shared);assert current==symbols(reference) and '__cfi_check' in current
(O/'actual-defined-symbols.txt').write_text('\n'.join(sorted(current))+'\n')
def dynamic(p):
 text=subprocess.check_output([str(readelf),'-d',str(p)],text=True)
 return [x.split('Shared library: ',1)[1] for x in text.splitlines() if '(NEEDED)' in x],[x.split('Library soname: ',1)[1] for x in text.splitlines() if '(SONAME)' in x]
assert dynamic(shared)==dynamic(reference)
archive=base/'android_arm_armv8-a_static/libnetworkstats.a';bind(archive);obj=O/'libnetworkstats-arm32.o';cmd=[str(linker),'-r','--whole-archive',str(archive),'--no-whole-archive','-o',str(obj)];linked=subprocess.run(cmd,capture_output=True,text=True);(O/'arm32-link.log').write_text(linked.stdout+linked.stderr);assert linked.returncode==0 and not linked.stderr,(linked.stdout,linked.stderr);elf(obj,1,40,1)
text=subprocess.check_output([str(nm),'--defined-only','--demangle',str(obj)],text=True)
for name in ['android::bpf::gta3xlwifiLegacyDetail(','android::bpf::gta3xlwifiLegacyUidStats(','android::bpf::legacy::readStats(','android::bpf::legacy::addCounters(']:assert name in text,name
(O/'arm32-key-symbols.txt').write_text('\n'.join(line for line in text.splitlines() if 'gta3xlwifiLegacy' in line or 'android::bpf::legacy::' in line)+'\n')
jar=T/'out/soong/.intermediates/packages/modules/Connectivity/service-t/service-connectivity-tiramisu-pre-jarjar/android_common_apex31/javac/service-connectivity-tiramisu-pre-jarjar.jar';bind(jar)
with zipfile.ZipFile(jar) as z:
 assert b'mLegacySnapshot' in z.read('com/android/server/net/NetworkStatsFactory.class');assert b'ro.gta3xlwifi.legacy_networking' in z.read('com/android/server/net/NetworkStatsFactory$Dependencies.class')
expected={'Image':'33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553','dtbo.img':'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b','vendor.img':'a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a'}
for name,h in expected.items():path=T/'device/samsung/gta3xlwifi/prebuilt'/name;assert sha(path)==h;bind(path)
for path in [nm,readelf,linker]:bind(path)
for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'inputs_sha256':inputs,'installed_arm64_expanded_apex_library_sha256':sha(installed),'arm32_archive_sha256':sha(archive),'arm32_link_command':cmd,'arm32_relocatable_class':32,'arm32_machine':40,'arm32_archive_variant':'android_arm_armv8-a_static','dynamic_exports_match_complete_isolated_module':len(current),'soname_needed_match_isolated_module':True,'real_java_legacy_fields_present':True,'expected_adapter_cases':a.expected_adapter_cases,'installed_rc_group_contract_checked':a.expected_adapter_cases==37,'host_tested_runtime_inputs_identical':True,'original_kernel_vendor_dtbo_preserved':expected,'android_tests_executed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: real ARM64 expanded-APEX module, ARM32 archive, Java JAR and host-tested source identities; original inputs unchanged')
