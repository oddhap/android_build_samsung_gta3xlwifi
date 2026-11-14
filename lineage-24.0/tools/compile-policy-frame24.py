#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build actual append-only private Binder transport and complete netd outside TOP.

Build/link and wire compatibility evidence only. No framework client, kernel
execution, selected source change or networking readiness is implied.
"""
import argparse,fcntl,hashlib,json,os,re,shlex,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','base-report','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve()
assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={};commands=[]
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
def run(label,cmd):
 commands.append(cmd);r=subprocess.run(cmd,cwd=T,capture_output=True,text=True)
 (O/(label+'.log')).write_text(r.stdout+r.stderr)
 assert r.returncode==0,(label,r.stderr[-12000:]);return r.stdout
ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';aidl=T/'out/host/linux-x86/bin/aidl';bind(ninja);bind(aidl);bind(Path(__file__));bind(a.base_report)
base=json.loads(a.base_report.read_text());assert base['passed'] and base['full_netd_linked']
for path,h in base['inputs_sha256'].items():assert sha(Path(path))==h,'Changed prerequisite '+path
for q in S.rglob('*'):
 if q.is_file():bind(q)
audit=Path(__file__).with_name('audit-port.py');bind(audit)
def check(name):run(name,[sys.executable,str(audit),str(T),str(a.snapshot),str(O/(name+'.json'))])
def query(target):
 raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);assert len(raw.splitlines())==1
 args=[]
 for x in shlex.split(raw):
  if x.startswith('@'):bind(T/x[1:]);args.extend(shlex.split((T/x[1:]).read_text()))
  else:args.append(x)
 if args[0]=='PWD=/proc/self/cwd':args=args[1:]
 if Path(args[0]).name=='ccache':args=args[1:]
 return args
check('source-before')
try:
 binder=S/'binder';actual=T/'system/netd/server/binder';generated=O/'generated';headers=O/'include';java=O/'java'
 for q in [generated,headers,java]:q.mkdir()
 private='com/android/internal/net/IGta3xlwifiNetpolicy.aidl';oem='com/android/internal/net/IOemNetd.aidl';unsol='com/android/internal/net/IOemNetdUnsolicitedEventListener.aidl'
 for name in [private,oem]:
  run(Path(name).stem+'-cpp',[str(aidl),'--lang=cpp','--min_sdk_version=10000','-I'+str(binder),'-I'+str(actual),'-o',str(generated),'-h',str(headers),str(binder/name)])
  run(Path(name).stem+'-java',[str(aidl),'--lang=java','--min_sdk_version=10000','-I'+str(binder),'-I'+str(actual),'-o',str(java),str(binder/name)])
 # Actual old API dump against the append-only new interface.
 old=O/'api-old';new=O/'api-new'
 for directory,root in [(old,actual),(new,binder)]:
  run(directory.name,[str(aidl),'--dumpapi','-I'+str(root),'-I'+str(actual),'--out='+str(directory),str(root/oem),str(actual/unsol),*([str(binder/private)] if root==binder else [])])
 run('oem-API-compatible',[str(aidl),'--checkapi=compatible',str(old),str(new)])
 text=(java/'com/android/internal/net/IOemNetd.java').read_text()
 assert re.search(r'TRANSACTION_isAlive\s*=\s*\(android.os.IBinder.FIRST_CALL_TRANSACTION \+ 0\)',text)
 assert re.search(r'TRANSACTION_registerOemUnsolicitedEventListener\s*=\s*\(android.os.IBinder.FIRST_CALL_TRANSACTION \+ 1\)',text)
 assert re.search(r'TRANSACTION_getGta3xlwifiNetpolicy\s*=\s*\(android.os.IBinder.FIRST_CALL_TRANSACTION \+ 2\)',text)
 server_template=base['compile_commands'][0]
 def compile_cpp(name,source,template):
  command=template.copy();command[command.index('-o')+1]=str(O/(name+'.o'));command[command.index('-MF')+1]=str(O/(name+'.o.d'));command[-1]=str(source)
  command[1:1]=['-I'+str(headers),'-I'+str(S)];run(name+'-compile',command);return str(O/(name+'.o'))
 policy=compile_cpp('Gta3xlwifiSocketPolicyProjection',S/'Gta3xlwifiSocketPolicyProjection.cpp',server_template)
 frame=compile_cpp('Gta3xlwifiPolicyFrame',S/'Gta3xlwifiPolicyFrame.cpp',server_template)
 listener_target='out/soong/.intermediates/system/netd/server/netd/android_arm64_armv8-a_cfi/obj/system/netd/server/OemNetdListener.o';listener_template=query(listener_target)
 assert '-flto' in listener_template and any(x.startswith('-fsanitize=') and 'cfi' in x for x in listener_template)
 service=compile_cpp('Gta3xlwifiNetpolicyService',S/'Gta3xlwifiNetpolicyService.cpp',listener_template)
 listener=compile_cpp('OemNetdListener',S/'OemNetdListener.cpp',listener_template)
 old_dso='out/soong/.intermediates/system/netd/server/oemnetd_aidl_interface-cpp/android_arm64_armv8-a_shared/unstripped/oemnetd_aidl_interface-cpp.so';dso_link=query(old_dso)
 old_oem=next(x for x in dso_link if x.endswith('/IOemNetd.o'));template=query(old_oem)
 new_oem=compile_cpp('IOemNetd',generated/'com/android/internal/net/IOemNetd.cpp',template)
 new_private=compile_cpp('IGta3xlwifiNetpolicy',generated/'com/android/internal/net/IGta3xlwifiNetpolicy.cpp',template)
 dso_link[dso_link.index(old_oem)]=new_oem;dso_link.insert(1,new_private);dso_link[dso_link.index('-o')+1]=str(O/'oemnetd_aidl_interface-cpp.so');run('oem-link',dso_link)
 # Compile the real Java client stubs against current Android framework bytecode.
 unsol_java=java/'com/android/internal/net/IOemNetdUnsolicitedEventListener.java'
 run('unsolicited-java',[str(aidl),'--lang=java','--min_sdk_version=10000','-I'+str(actual),'-o',str(java),str(actual/unsol)])
 framework=T/'out/soong/.intermediates/frameworks/base/framework-minus-apex/android_common/jarjar/turbine/framework.jar';bind(framework)
 javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';bind(javac)
 (O/'java-classes').mkdir();run('client-java',[str(javac),'-source','21','-target','21','-classpath',str(framework),'-d',str(O/'java-classes'),*map(str,java.rglob('*.java'))])
 full=base['full_netd_link_command'].copy();old_archive=next(x for x in full if x.endswith('/libnetd_server.a'))
 archive=O/'libnetd_server.a';bind(old_archive);shutil.copyfile(old_archive,archive)
 ar=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin/llvm-ar';bind(ar)
 run('server-archive',[str(ar),'rD',str(archive),policy,frame,service])
 full[full.index(old_archive)]=str(archive);assert full.count(listener_target)==1;full[full.index(listener_target)]=listener
 oem_link_input=next(x for x in full if x.endswith('/oemnetd_aidl_interface-cpp.so'));bind(T/oem_link_input);full[full.index(oem_link_input)]=str(O/'oemnetd_aidl_interface-cpp.so')
 full[full.index('-o')+1]=str(O/'netd');run('full-netd-link',full)
 readelf=ar.with_name('llvm-readelf');bind(readelf)
 def needed(path):return re.findall(r'\(NEEDED\).*\[(.*?)\]',subprocess.check_output([str(readelf),'-d',str(path)],text=True))
 assert needed(O/'netd')==base['full_netd_needed']
 assert needed(O/'oemnetd_aidl_interface-cpp.so')==needed(T/old_dso)
 for path,h in inputs.items():assert sha(Path(path))==h,'Changed '+path
 check('source-after')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'old_oem_ordinals_preserved':True,'oem_api_append_only_compatible':True,'actual_AIDL_cpp_java_generated':True,'actual_java_client_stubs_compiled':True,'full_netd_linked':True,'original_CFI_flags_retained':True,'netd_sha256':sha(O/'netd'),'oem_DSO_sha256':sha(O/'oemnetd_aidl_interface-cpp.so'),'commands':commands,'inputs_sha256':inputs,'framework_client_implemented':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: append-only AIDL C++/Java, actual client stubs, complete netd/DSO and source audits')
finally:
 if not (O/'source-after.json').exists():check('source-after')
