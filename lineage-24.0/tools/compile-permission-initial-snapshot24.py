#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile actual complete Android17 permission Kotlin module with ordered snapshots.

Source/API typechecking only, outside TOP; no source/output/API selection or
framework runtime/network readiness claim. Original compiler flags are retained.
"""
import argparse,fcntl,hashlib,json,os,shlex,subprocess,sys,xml.etree.ElementTree as ET,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
audit=Path(__file__).with_name('audit-port.py');bind(audit);bind(Path(__file__))
def check(name):subprocess.run([sys.executable,str(audit),str(T),str(a.snapshot),str(O/name)],check=True)
check('source-before.json')
try:
 originals={'PermissionService.kt':T/'frameworks/base/services/permission/java/com/android/server/permission/access/permission/PermissionService.kt','AccessCheckingService.kt':T/'frameworks/base/services/permission/java/com/android/server/permission/access/AccessCheckingService.kt','PermissionBpfMap.java':T/'frameworks/base/services/core/java/com/android/server/permission/PermissionBpfMap.java'}
 for name,path in originals.items():assert (S/(name+'.reference')).read_bytes()==path.read_bytes();bind(path);bind(S/name)
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';bind(ninja);target='out/soong/.intermediates/frameworks/base/services/permission/services.permission-pre-jarjar/android_common/kotlin/services.permission-pre-jarjar.jar'
 raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);(O/'original-soong-command.txt').write_text(raw)
 segments=[shlex.split(s) for s in raw.split(' && ')];candidates=[s for s in segments if s and s[0]=='external/kotlinc/bin/kotlinc'];assert len(candidates)==1;command=candidates[0]
 assert '-no-jdk' in command and '-no-stdlib' in command and command[command.index('-jvm-target')+1]=='21' and '-Xjvm-default=all' in command
 build_arg=next(x for x in command if x.startswith('-Xbuild-file='));xml=T/build_arg.split('=',1)[1];bind(xml);tree=ET.parse(xml);root=tree.getroot();assert len(root)==1;module=root[0];module.set('outputDir',str(O/'classes'))
 classpaths=[Path(n.get('path')) for n in module.findall('classpath')];sources=[Path(n.get('path')) for n in module.findall('sources')];assert len(sources)==71 and len(classpaths)>50
 for path in classpaths+sources:bind(path)
 javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';javap=javac.with_name('javap');bind(javac);bind(javap);java_dir=O/'interface-classes';java_dir.mkdir()
 java_command=[str(javac),'-source','21','-target','21','-classpath',os.pathsep.join(map(str,classpaths)),'-d',str(java_dir),str(S/'PermissionBpfMap.java')]
 result=subprocess.run(java_command,cwd=T,capture_output=True,text=True);(O/'interface-compile.log').write_text(result.stdout+result.stderr);assert result.returncode==0,result.stderr
 interface=java_dir/'com/android/server/permission/PermissionBpfMap.class';assert interface.is_file();interface_jar=O/'permission-snapshot-interface.jar'
 with zipfile.ZipFile(interface_jar,'w',zipfile.ZIP_DEFLATED) as z:z.write(interface,str(interface.relative_to(java_dir)))
 module.insert(0,ET.Element('classpath',{'path':str(interface_jar)}));changed=[]
 for node in module.findall('sources'):
  path=Path(node.get('path'))
  if path.name in ['AccessCheckingService.kt','PermissionService.kt']:node.set('path',str(S/path.name));changed.append(path.name)
 assert sorted(changed)==['AccessCheckingService.kt','PermissionService.kt'];new_xml=O/'kotlinc-build.xml';tree.write(new_xml,encoding='unicode');(O/'empty').mkdir();(O/'header-classes').mkdir();(O/'classes').mkdir()
 command=[str(T/command[0]),*command[1:]];command[command.index(build_arg)]='-Xbuild-file='+str(new_xml);command[command.index('-kotlin-home')+1]=str(O/'empty')
 for i,arg in enumerate(command):
  if arg.startswith('plugin:org.jetbrains.kotlin.jvm.abi:outputDir='):command[i]='plugin:org.jetbrains.kotlin.jvm.abi:outputDir='+str(O/'header-classes')
 bind(T/'external/kotlinc/bin/kotlinc');bind(T/'external/kotlinc/lib/kotlin-compiler.jar');bind(T/'external/kotlinc/lib/jvm-abi-gen.jar')
 result=subprocess.run(command,cwd=T,capture_output=True,text=True,env={**os.environ,'JAVA_HOME':str(T/'prebuilts/jdk/jdk21/linux-x86')});(O/'kotlin-compile.log').write_text(result.stdout+result.stderr);assert result.returncode==0,result.stderr[-16000:]
 classes=list((O/'classes').rglob('*.class'));bind(T/target)
 with zipfile.ZipFile(T/target) as original_jar:original_classes={name for name in original_jar.namelist() if name.endswith('.class')}
 actual_classes={str(path.relative_to(O/'classes')) for path in classes};assert actual_classes==original_classes,(sorted(original_classes-actual_classes),sorted(actual_classes-original_classes))
 package='com.android.server.permission.access.permission.PermissionService';output=subprocess.check_output([str(javap),'-p','-c','-classpath',str(O/'classes')+os.pathsep+str(interface_jar),package],text=True);(O/'permission-service-javap.txt').write_text(output)
 # Registration's generated lambda carries the actual ordered snapshot logic.
 found=[]
 for path in classes:
  if not path.name.startswith('PermissionService'):continue
  data=path.read_bytes()
  if b'setInitialUidPermissions' in data:found.append(str(path.relative_to(O)))
 assert found and b'setInitialUidPermissions' in interface.read_bytes()
 for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
 check('source-after.json')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'actual_Kotlin_sources':len(sources),'actual_classpath_jars':len(classpaths),'class_count':len(classes),'original_class_inventory_preserved':True,'initial_callback_callsite_classes':found,'interface_sha256':sha(interface),'inputs_sha256':inputs,'java_command':java_command,'kotlin_command':command,'source_or_API_selection_changed':False,'framework_runtime_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual71-source Android17 permission module and new default interface compiled;',len(classes),'classes')
finally:
 if not (O/'source-after.json').exists():check('source-after.json')
