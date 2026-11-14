#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the actual snapshot interface API and strictly check old API compatibility.

Uses current Android metalava/JDK21 outside TOP. No API-lint/compatibility baseline,
ignored errors or selected source/API changes. Includes a removed-method negative control.
"""
import argparse, fcntl, hashlib, json, os, subprocess, xml.etree.ElementTree as ET
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve()
assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
original=T/'frameworks/base/services/api/current.txt'
assert original.read_bytes()==(S/'current.txt.reference').read_bytes()
native=json.loads(a.native_report.read_text());assert native['passed']
xml=a.native_report.parent/'kotlinc-build.xml'
classpath=os.pathsep.join(n.get('path') for n in ET.parse(xml).getroot()[0].findall('classpath'))
metalava=T/'out/host/linux-x86/bin/metalava'
env={**os.environ,'PATH':str(T/'prebuilts/jdk/jdk21/linux-x86/bin')+os.pathsep+os.environ['PATH']}
commands=[]
def run(name,args,ok=True):
 cmd=[str(metalava),'main',*args];commands.append(cmd)
 result=subprocess.run(cmd,cwd=T,env=env,capture_output=True,text=True)
 (O/(name+'.log')).write_text(result.stdout+result.stderr)
 assert (result.returncode==0)==ok,(name,result.returncode,result.stderr[-6000:])
 return result
# Generate directly from the actual Java source, resolving against the real module classpath.
for name,source in [('original',S/'PermissionBpfMap.java.reference'),('candidate',S/'PermissionBpfMap.java')]:
 directory=O/name/'com/android/server/permission';directory.mkdir(parents=True);copy=directory/'PermissionBpfMap.java';copy.write_bytes(source.read_bytes())
 run(name,['--source-files',str(copy),'--classpath',classpath,'--java-source','21',
  '--show-annotation','android.annotation.SystemApi(client=android.annotation.SystemApi.Client.SYSTEM_SERVER)',
  '--api',str(O/(name+'.txt')),'--format','2.0'])
def section(text):
 start=text.index('  @FlaggedApi("android.permission.flags.access_local_network_permission_enabled") public interface PermissionBpfMap {')
 return text[start:text.index('\n  }',start)+4]
assert section((O/'original.txt').read_text())==section(original.read_text())
assert section((O/'candidate.txt').read_text())==section((S/'current.txt').read_text())
expected='    method public default void setInitialUidPermissions(@NonNull int[], @NonNull int[], @NonNull android.util.SparseIntArray);\n'
assert (S/'current.txt').read_text().replace(expected,'',1)==original.read_text()
# Check the complete original server API against the complete candidate signature.
run('compatibility',[str(S/'current.txt'),'--check-compatibility:api:released',str(original)])
negative=O/'removed-method.txt';negative.write_text((S/'current.txt').read_text().replace('    method public void removeAppId(int);\n','',1))
result=run('negative-removed-method',[str(negative),'--check-compatibility:api:released',str(original)],False)
assert 'RemovedMethod' in result.stdout+result.stderr
inputs=[Path(__file__),original,S/'current.txt',S/'PermissionBpfMap.java',S/'PermissionBpfMap.java.reference',a.native_report,metalava,T/'out/host/linux-x86/framework/metalava.jar']
report={'passed':True,'scope':__doc__,'generated_original_and_candidate_match':True,'only_default_method_added':True,'complete_server_api_compatible':True,'removed_method_control_rejected':True,'input_sha256':{str(q):sha(q) for q in inputs},'commands':commands,'selected_API_changed':False,'flash_ready':False}
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: generated API exact; complete server API compatible; removed-method control rejected')
