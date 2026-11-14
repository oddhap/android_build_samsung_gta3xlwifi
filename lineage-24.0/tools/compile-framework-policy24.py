#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile actual framework policy routing with current Connectivity module/API classes.

Five actual changed Java sources plus generated Binder stubs, outside TOP. This
is compilation evidence; stats/event/boot admission and final Soong selection
remain separate gates, not networking Ready.
"""
import argparse,fcntl,hashlib,json,os,subprocess,sys,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','client-report','permission-report','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();inputs={}
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
client=json.loads(a.client_report.read_text());permission=json.loads(a.permission_report.read_text());assert client['passed'] and permission['passed'] and permission['class_count']==155
interface=a.permission_report.parent/'permission-snapshot-interface.jar'
with zipfile.ZipFile(interface) as z:assert hashlib.sha256(z.read('com/android/server/permission/PermissionBpfMap.class')).hexdigest()==permission['interface_sha256']
module=T/'out/soong/.intermediates/packages/modules/Connectivity/service/service-connectivity-pre-jarjar/android_common_apex31/javac/service-connectivity-pre-jarjar.jar'
for path in [Path(__file__),a.client_report,a.permission_report,interface,module]:bind(path)
audit=Path(__file__).with_name('audit-port.py');bind(audit)
def check(name):subprocess.run([sys.executable,str(audit),str(T),str(a.snapshot),str(O/(name+'.json'))],check=True)
check('source-before')
try:
 command=next(c.copy() for c in client['commands'] if Path(c[0]).name=='javac');command=[x for x in command if not x.endswith('/Gta3xlwifiNetpolicyClient.java')]
 classes=O/'classes';classes.mkdir();command[command.index('-d')+1]=str(classes)
 cp=command.index('-classpath')+1;command[cp]=str(interface)+os.pathsep+str(module)+os.pathsep+command[cp]
 for path in command[cp].split(os.pathsep):bind(path)
 for path in command:
  if path.endswith('.java'):bind(path)
 new=list((S/'java').rglob('*.java'));assert len(new)==5;command+=list(map(str,new))
 for path in new:bind(path)
 result=subprocess.run(command,cwd=T,capture_output=True,text=True);(O/'compile.log').write_text(result.stdout+result.stderr);assert result.returncode==0,result.stderr[-15000:]
 for path in ['com/android/server/BpfNetMaps.class','com/android/server/connectivity/PermissionMonitor.class','com/android/server/Gta3xlwifiNetpolicyBackend.class','com/android/server/Gta3xlwifiPermissionCollector.class']:assert (classes/path).is_file()
 for path,h in inputs.items():assert sha(path)==h
 check('source-after')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'actual_changed_Java_sources':5,'inputs_sha256':inputs,'command':command,'classes':sorted(str(p.relative_to(classes)) for p in classes.rglob('*.class')),'private_branch_before_map_initialization':True,'actual_framework_runtime_tested':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual BpfNetMaps/PermissionMonitor/backend/client/receiver compiled; source audits passed')
finally:
 if not (O/'source-after.json').exists():check('source-after')
