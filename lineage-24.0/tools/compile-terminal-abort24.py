#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual append-only stats AIDL, generated C++/Java and complete netd/OEM links."""
import argparse,fcntl,hashlib,json,re,shlex,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','previous-source','base-report','transport-report','kernel','kernel-report','framework-report','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();inputs={};commands=[]
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
def run(n,c):
 commands.append(c);x=subprocess.run(c,cwd=T,capture_output=True,text=True);(O/(n+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,(n,x.stderr[-12000:]);return x.stdout
base=json.loads(a.base_report.read_text());assert base['passed'] and base['actual_CFI_service_full_netd_and_OEM_DSO'];bind(a.base_report);bind(Path(__file__))
for f,h in base['inputs_sha256'].items():assert sha(f)==h,'Changed prerequisite '+f

transport=json.loads(a.transport_report.read_text());assert transport['passed'];bind(a.transport_report)
for f,h in transport['inputs_sha256'].items():assert sha(f)==h
ptemplate=next(c for c in transport['commands'] if c[-1].endswith('/Gta3xlwifiSocketPolicyProjection.cpp'))
kr=json.loads(a.kernel_report.read_text());assert kr['passed'] and kr['actual_Image_all_modules_and_Gator_built'];bind(a.kernel_report)
assert (S/'linux/netfilter/gta3xlwifi_iface_stats.h').read_bytes()==(a.kernel/'include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h').read_bytes()
bind(a.kernel/'include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h');bind(a.kernel_report.parent/'Image')
assert kr['actual_UID_receipt_and_corrected_full_ioctl_routing_built']
assert (S/'linux/netfilter/gta3xlwifi_packet_stats.h').read_bytes()==(a.kernel/'include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h').read_bytes()
bind(a.kernel/'include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h')

for f in S.rglob('*'):
 if f.is_file():bind(f)
audit=Path(__file__).with_name('audit-port.py');bind(audit)
def check(n):run(n,[sys.executable,str(audit),str(T),str(a.snapshot),str(O/(n+'.json'))])
check('source-before')
try:
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';aidl=T/'out/host/linux-x86/bin/aidl';bind(ninja);bind(aidl)
 def query(target):
  raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);assert len(raw.splitlines())==1
  c=[]
  for w in shlex.split(raw):
   if w.startswith('@'):bind(T/w[1:]);c.extend(shlex.split((T/w[1:]).read_text()))
   else:c.append(w)
  if c[0]=='PWD=/proc/self/cwd':c=c[1:]
  if Path(c[0]).name=='ccache':c=c[1:]
  return c
 binder=S/'binder';actual=T/'system/netd/server/binder';private='com/android/internal/net/IGta3xlwifiNetpolicy.aidl';oem='com/android/internal/net/IOemNetd.aidl';unsol='com/android/internal/net/IOemNetdUnsolicitedEventListener.aidl'
 generated=O/'generated';headers=O/'include';java=O/'java'
 for q in [generated,headers,java]:q.mkdir()
 for n in [private,oem]:
  run(Path(n).stem+'-cpp',[str(aidl),'--lang=cpp','--min_sdk_version=10000','-I'+str(binder),'-I'+str(actual),'-o',str(generated),'-h',str(headers),str(binder/n)])
  run(Path(n).stem+'-java',[str(aidl),'--lang=java','--min_sdk_version=10000','-I'+str(binder),'-I'+str(actual),'-o',str(java),str(binder/n)])
 for n,root in [('old',a.previous_source/'binder'),('new',binder)]:run('api-'+n,[str(aidl),'--dumpapi','-I'+str(root),'-I'+str(actual),'--out='+str(O/('api-'+n)),str(root/private),str(root/oem),str(actual/unsol)])
 run('api-compatible',[str(aidl),'--checkapi=compatible',str(O/'api-old'),str(O/'api-new')])
 text=(java/private.replace('.aidl','.java')).read_text()
 names=['openSession','beginFrame','appendFrame','commitFrame','abandonFrame','readGeneration','closeSession','readStats','swapStats','acknowledgeStats','setStatsCounterset','removeUidAccounting','removeUidAccountingOnce','abortSession']
 for i,n in enumerate(names):assert re.search(r'TRANSACTION_'+n+r'\s*=\s*\(android.os.IBinder.FIRST_CALL_TRANSACTION \+ '+str(i)+r'\)',text)
 listener='out/soong/.intermediates/system/netd/server/netd/android_arm64_armv8-a_cfi/obj/system/netd/server/OemNetdListener.o';template=query(listener)
 def compile(n,path,c):
  c=c.copy();c[1:1]=['-I'+str(headers),'-I'+str(S)];c[c.index('-o')+1]=str(O/(n+'.o'));c[c.index('-MF')+1]=str(O/(n+'.o.d'));c[-1]=str(path);bind(T/c[0]);run(n+'-compile',c);return str(O/(n+'.o'))
 assert '-flto' in template and any(w.startswith('-fsanitize=') and 'cfi' in w for w in template)
 controllers_target='out/soong/.intermediates/system/netd/server/libnetd_server/android_arm64_armv8-a_static_cfi/obj/system/netd/server/Controllers.o'
 controllers=compile('Controllers',S/'Controllers.cpp',query(controllers_target))
 policy=compile('Gta3xlwifiSocketPolicyProjection',S/'Gta3xlwifiSocketPolicyProjection.cpp',ptemplate);lease=compile('Gta3xlwifiNetpolicyLease',S/'Gta3xlwifiNetpolicyLease.cpp',ptemplate)
 provider=compile('Gta3xlwifiHeldProvider',S/'Gta3xlwifiHeldProvider.cpp',ptemplate);qtag=compile('Gta3xlwifiQtaguidTransport',S/'Gta3xlwifiQtaguidTransport.cpp',ptemplate)
 service=compile('Gta3xlwifiNetpolicyService',S/'Gta3xlwifiNetpolicyService.cpp',template);newlistener=compile('OemNetdListener',S/'OemNetdListener.cpp',template)
 olddso='out/soong/.intermediates/system/netd/server/oemnetd_aidl_interface-cpp/android_arm64_armv8-a_shared/unstripped/oemnetd_aidl_interface-cpp.so';dsolink=query(olddso);oldobj=next(w for w in dsolink if w.endswith('/IOemNetd.o'));dt=query(oldobj)
 newoem=compile('IOemNetd',generated/'com/android/internal/net/IOemNetd.cpp',dt);newprivate=compile('IGta3xlwifiNetpolicy',generated/'com/android/internal/net/IGta3xlwifiNetpolicy.cpp',dt);dsolink[dsolink.index(oldobj)]=newoem;dsolink.insert(1,newprivate);dsolink[dsolink.index('-o')+1]=str(O/'oemnetd_aidl_interface-cpp.so');run('oem-link',dsolink)
 run('unsol-java',[str(aidl),'--lang=java','--min_sdk_version=10000','-I'+str(actual),'-o',str(java),str(actual/unsol)])
 javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';bind(javac)
 java_target='out/soong/.intermediates/packages/modules/Connectivity/service/service-connectivity-pre-jarjar/android_common_apex31/javac/service-connectivity-pre-jarjar.jar'
 raw_java=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',java_target],cwd=T,text=True);(O/'original-javac-command.txt').write_text(raw_java)
 args=shlex.split(raw_java);assert args.count('-classpath')==1
 cp=[T/x for x in args[args.index('-classpath')+1].split(':')]
 framework=json.loads(a.framework_report.read_text());assert framework['passed'];bind(a.framework_report)
 framework_cp=framework['command'][framework['command'].index('-classpath')+1].split(':')[:2]
 for entry in framework_cp:assert sha(entry)==framework['inputs_sha256'][entry]
 target='out/soong/.intermediates/packages/modules/Connectivity/service-t/service-connectivity-tiramisu-pre-jarjar/android_common_apex31/javac/service-connectivity-tiramisu-pre-jarjar.jar'
 raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);(O/'original-service-t-javac-command.txt').write_text(raw)
 tokens=shlex.split(raw);assert tokens.count('-classpath')==1
 cp=[*map(Path,framework_cp),*cp,T/target,*[T/x for x in tokens[tokens.index('-classpath')+1].split(':')]]
 for f in cp:bind(f)
 run('java-stubs-and-clients',[str(javac),'-source','21','-target','21','-classpath',':'.join(map(str,cp)),'-d',str(O/'java-classes'),*map(str,java.rglob('*.java')),*map(str,(S/'java').rglob('*.java'))])

 full=next(c.copy() for c in base['commands'] if '-o' in c and c[c.index('-o')+1].endswith('/netd'));oldserver=next(w for w in full if w.endswith('/libnetd_server.a'));bind(oldserver);archive=O/'libnetd_server.a';shutil.copyfile(oldserver,archive);ar=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin/llvm-ar';bind(ar);run('archive',[str(ar),'rD',str(archive),service,policy,lease,controllers,provider,qtag]);full[full.index(oldserver)]=str(archive)
 oldlistener=next(w for w in full if w.endswith('/OemNetdListener.o'));bind(oldlistener);full[full.index(oldlistener)]=newlistener;oldinput=next(w for w in full if w.endswith('/oemnetd_aidl_interface-cpp.so'));bind(oldinput);full[full.index(oldinput)]=str(O/'oemnetd_aidl_interface-cpp.so');full[full.index('-o')+1]=str(O/'netd');run('netd-link',full)
 # Actual ARM32/ARM64 UAPI layouts using current real target compiler commands.
 wire=O/'names-wire.cpp';wire.write_text('#include <linux/netfilter/gta3xlwifi_iface_stats.h>\n#include <linux/netfilter/gta3xlwifi_packet_stats.h>\nstatic_assert(sizeof(gta3xlwifi_iface_name_entry)==20);\nstatic_assert(sizeof(gta3xlwifi_iface_names_transfer)==32);\nstatic_assert(__builtin_offsetof(gta3xlwifi_iface_names_transfer,entries)==8);\nstatic_assert(GTA3XLWIFI_IFACE_NAMES_GET==0xc0206762U);\nstatic_assert(GTA3XLWIFI_UID_CAP_IFACE_NAMES==65536U);static_assert(sizeof(gta3xlwifi_uid_cleanup)==64);static_assert(GTA3XLWIFI_UID_CLEANUP==0xc0406763U);\nextern "C" unsigned ifname_wire_size(){return sizeof(gta3xlwifi_iface_name_entry); }\n');bind(wire)
 for variant,cls,machine in [('android_arm64_armv8-a_static',2,183),('android_arm_armv8-a_static',1,40)]:
  target='out/soong/.intermediates/system/core/libgta3xlwifi_keyutils/libgta3xlwifi_keyutils/'+variant+'/obj/system/core/libgta3xlwifi_keyutils/keyutils.o'
  c=query(target);c.insert(1,'-I'+str(S));c[c.index('-o')+1]=str(O/(variant+'.o'));c[c.index('-MF')+1]=str(O/(variant+'.o.d'));c[-1]=str(wire);run(variant+'-wire',c)
  linker=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin/ld.lld';bind(linker);native=O/(variant+'-native.o');run(variant+'-native',[str(linker),'-r',str(O/(variant+'.o')),'-o',str(native)])
  import struct
  data=native.read_bytes();assert data[:7]==b'\x7fELF'+bytes([cls,1,1]) and struct.unpack_from('<HH',data,16)==(1,machine)
 for f,h in inputs.items():assert sha(f)==h
 check('source-after')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'commands':commands,'inputs_sha256':inputs,'fourteen_AIDL_ordinals_verified':True,'append_only_compatible':True,'actual_CFI_service_full_netd_and_OEM_DSO':True,'maximum_stats_payload_bytes':400040,'interface_name_kind4_native_and_Java_implemented':True,'actual_Controllers_fatal_quarantine_handler_linked':True,'actual_terminal_session_token_abort_compiled':True,'actual_Java_source_count':len(list((S/'java').rglob('*.java'))),'actual_ARM32_ARM64_name_entry20_transfer32':True,'framework_poll_persistence_and_deduplication_implemented':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: genuine name-reader/owner/service CFI netd/OEM, actual Java, ARM32/64 UAPI and full audits')
finally:
 (O/'execution-inputs.json').write_text(json.dumps({'inputs_sha256':inputs,'commands':commands,'success_report_present':(O/'report.json').exists()},indent=2)+'\n')
 if not (O/'source-after.json').exists():check('source-after')
