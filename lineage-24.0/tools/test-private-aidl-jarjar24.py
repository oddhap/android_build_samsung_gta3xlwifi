#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay actual A17 SDK compilation and jarjar; compare real native descriptors and16 ordinals.

Actual Android Binder execution and complete Soong/APEX composition remain separate.
"""
import argparse,fcntl,hashlib,json,re,subprocess,sys,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','java-report','native-report','excludes','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={};commands=[]
def bind(f):f=Path(f).resolve();inputs[str(f)]=sha(f)
def run(name,c):
 commands.append(c);x=subprocess.run(c,cwd=T,capture_output=True,text=True);(O/(name+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,(name,x.stderr[-8000:]);return x.stdout
r=json.loads(a.java_report.read_text());n=json.loads(a.native_report.read_text());assert r['passed'] and r['actual_private_ClatCoordinator_compiled'] and r['actual_Soong_Android_core_modules'] and n['passed'] and n['sixteen_AIDL_ordinals_verified']
for f,h in {**r['inputs_sha256'],**n['inputs_sha256']}.items():assert sha(Path(f))==h,f
for f in [Path(__file__),a.java_report,a.native_report,a.excludes]:bind(f)
audit=Path(__file__).with_name('audit-port.py');bind(audit)
def check(label):run(label,[sys.executable,str(audit),str(T),str(a.snapshot),str(O/(label+'.json'))])
check('source-before')
try:
 cmd=r['command'].copy();cmd[cmd.index('-d')+1]=str(O/'classes');run('actual-java',cmd)
 jar=O/'candidate.jar'
 with zipfile.ZipFile(jar,'w',zipfile.ZIP_DEFLATED) as z:
  for f in sorted((O/'classes').rglob('*.class')):bind(f);z.write(f,f.relative_to(O/'classes').as_posix())
 gen=T/'packages/modules/Connectivity/tools/gen_jarjar.py';original=T/'packages/modules/Connectivity/service/jarjar-excludes.txt';jarjar=T/'out/host/linux-x86/framework/jarjar.jar';jdk=T/'prebuilts/jdk/jdk21/linux-x86/bin';java=jdk/'java';javap=jdk/'javap'
 for f in [gen,original,jarjar,java,javap,jar]:bind(f)
 fixed=O/'jarjar-excludes.txt';fixed.write_text(original.read_text()+'\n'+a.excludes.read_text());bind(fixed)
 identities=['IGta3xlwifiNetpolicy','IOemNetd','IOemNetdUnsolicitedEventListener'];results={}
 native_root=a.native_report.parent/'generated/com/android/internal/net'
 for mode,excludes in [('original',original),('fixed',fixed)]:
  rules=O/(mode+'-rules.txt');run(mode+'-generate',[sys.executable,str(gen),str(jar),'--prefix','android.net.connectivity','--excludes',str(excludes),'--output',str(rules)]);bind(rules)
  target=O/(mode+'.jar');run(mode+'-jarjar',[str(java),'-jar',str(jarjar),'process',str(rules),str(jar),str(target)]);bind(target)
  with zipfile.ZipFile(target) as z:names=set(z.namelist())
  records=[]
  for name in identities:
   native=native_root/(name+'.cpp')
   if name=='IOemNetdUnsolicitedEventListener':native=T/'out/soong/.intermediates/system/netd/server/oemnetd_aidl_interface-cpp-source/gen/com/android/internal/net/IOemNetdUnsolicitedEventListener.cpp'
   bind(native);expected='com.android.internal.net.'+name;assert '"'+expected+'"' in native.read_text()
   clazz=expected if expected.replace('.','/')+'.class' in names else 'android.net.connectivity.'+expected
   text=run(mode+'-'+name,[str(javap),'-constants','-classpath',str(target),clazz]);match=re.search(r'DESCRIPTOR = "([^"]+)";',text);assert match,text;records.append({'interface':name,'native_descriptor':expected,'java_class':clazz,'java_descriptor':match[1],'matches_native':match[1]==expected})
   if mode=='fixed':
    assert clazz==expected and match[1]==expected
    original_classes=[f.relative_to(O/'classes').as_posix() for f in (O/'classes/com/android/internal/net').glob(name+'*.class')];assert original_classes and all(f in names for f in original_classes)
  results[mode]=records
  if mode=='fixed':
   text=run('fixed-ordinals',[str(javap),'-p','-constants','-classpath',str(target),'com.android.internal.net.IGta3xlwifiNetpolicy$Stub'])
   methods=['openSession','beginFrame','appendFrame','commitFrame','abandonFrame','readGeneration','closeSession','readStats','swapStats','acknowledgeStats','setStatsCounterset','removeUidAccounting','removeUidAccountingOnce','abortSession','pollLoopbackEvents','tagClatSocket']
   for i,name in enumerate(methods,1):assert re.search(r'TRANSACTION_'+name+r' = '+str(i)+r';',text),name
 for f,h in inputs.items():assert sha(Path(f))==h
 check('source-after');(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'actual_Java_source_count':r['actual_Java_source_count'],'results':results,'sixteen_post_jarjar_ordinals_verified':True,'actual_Soong_Android_core_modules':r['actual_Soong_Android_core_modules'],'inputs_sha256':inputs,'commands':commands,'selected_source_changed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(json.dumps(results))
finally:
 if not (O/'source-after.json').exists():check('source-after')
