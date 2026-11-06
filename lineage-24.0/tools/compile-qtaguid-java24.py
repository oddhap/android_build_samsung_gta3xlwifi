#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Typecheck the complete real A17 Connectivity tiramisu Java module in isolation.

Retains actual Soong javac/JDK21/system module/classpath/source lists. Only the
locked NetworkStatsFactory source is substituted. Generated-source extraction
and all class/annotation outputs stay outside TOP. Does not execute Android tests.
"""
import argparse,hashlib,json,shlex,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','staging','lock','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.staging.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);O.mkdir(parents=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
inputs={}
def bind(p):
 p=p.resolve();assert p.is_file(),p;inputs[str(p)]=sha(p)
lock=json.loads(a.lock.read_text());project=T/lock['project'];bind(a.lock);bind(Path(__file__))
assert subprocess.check_output(['git','-C',str(project),'rev-parse','HEAD'],text=True).strip()==lock['revision']
for row in lock['files']:
 assert sha(project/row['path'])==row['before_sha256'];assert sha(S/row['path'])==row['candidate_sha256'];bind(project/row['path']);bind(S/row['path'])
relative='out/soong/.intermediates/packages/modules/Connectivity/service-t/service-connectivity-tiramisu-pre-jarjar/android_common_apex31/javac';target=relative+'/service-connectivity-tiramisu-pre-jarjar.jar';ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja'
raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);(O/'soong-command.txt').write_text(raw);tokens=shlex.split(raw)
# Never execute the original shell rule: it removes production output directories.
separators={'&&',';','fi',')'};executed=[]
def run(cmd,label):
 r=subprocess.run(cmd,cwd=T,capture_output=True,text=True);(O/(label+'.log')).write_text(r.stdout+r.stderr);executed.append({'label':label,'command':cmd,'returncode':r.returncode});assert r.returncode==0,r.stderr[-16000:]
for name in ['srcjars','anno']:
 candidates=[i for i,t in enumerate(tokens) if Path(t).name=='zipsync' and tokens[i+1:i+3]==['-d',relative+'/'+name]];assert len(candidates)==1
 start=candidates[0];end=start
 while end<len(tokens) and tokens[end] not in separators:end+=1
 cmd=tokens[start:end];bind(T/cmd[0])
 for option in ['-d','-l']:
  at=cmd.index(option)+1;value=cmd[at];assert value.startswith(relative+'/');cmd[at]=str(O/value[len(relative)+1:])
 for value in cmd:
  if value.endswith('.jar') or value.endswith('.srcjar'):bind(T/value)
 run(cmd,'extract-'+name)
start=next(i for i,t in enumerate(tokens) if Path(t).name=='soong_javac_wrapper');end=start
while end<len(tokens) and tokens[end] not in separators:end+=1
cmd=tokens[start:end];assert Path(cmd[1]).name=='javac' and '-proc:none' in cmd and cmd[cmd.index('-source')+1]=='21' and cmd[cmd.index('-target')+1]=='21';bind(T/cmd[0]);bind(T/cmd[1])
for option in ['-d','-s']:
 at=cmd.index(option)+1;value=cmd[at];assert value.startswith(relative+'/');cmd[at]=str(O/value[len(relative)+1:]);Path(cmd[at]).mkdir(exist_ok=True)
classpath=cmd[cmd.index('-classpath')+1]
for value in classpath.split(':'):bind(T/value)
system=next(x.split('=',1)[1] for x in cmd if x.startswith('--system='))
for path in (T/system).rglob('*'):
 if path.is_file():bind(path)
substituted=0;sources=[];factory=str(Path(lock['project'])/lock['files'][0]['path'])
for index,value in enumerate(cmd):
 if not value.startswith('@'):continue
 original=value[1:];assert original.startswith(relative+'/')
 if original.endswith('/srcjars/list') or original.endswith('/anno/list'):
  path=O/original[len(relative)+1:];assert path.is_file();items=shlex.split(path.read_text())
 else:
  path=T/original;bind(path);items=shlex.split(path.read_text());assert factory in items
  substituted+=items.count(factory);items=[str(S/lock['files'][0]['path']) if x==factory else x for x in items]
 new=O/('sources-'+str(index)+'.rsp');new.write_text('\n'.join(shlex.quote(x) for x in items)+'\n');cmd[index]='@'+str(new)
 for item in items:
  assert item.endswith('.java'),item;source=Path(item) if Path(item).is_absolute() else T/item;bind(source);sources.append(str(source))
assert substituted==1 and len(sources)>30
baseline=T/target;bind(baseline);run(cmd,'javac')
classes=sorted((O/'classes').rglob('*.class'));assert len(classes)>30
for name in ['NetworkStatsFactory.class','NetworkStatsFactory$Dependencies.class']:
 assert (O/'classes/com/android/server/net'/name).is_file()
assert b'ro.gta3xlwifi.legacy_networking' in (O/'classes/com/android/server/net/NetworkStatsFactory$Dependencies.class').read_bytes()
for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
report={'passed':True,'scope':__doc__,'inputs_sha256':inputs,'source_lock':lock,'source_files_typechecked':len(sources),'class_files_produced':len(classes),'classes_sha256':{str(path.relative_to(O)):sha(path) for path in classes},'executed':executed,'production_outputs_unchanged':True,'android_tests_executed':False,'hardware_tested':False,'flash_ready':False}
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: complete Android17 Java module typechecked with actual JDK21/Soong APIs; '+str(len(sources))+' sources, '+str(len(classes))+' classes')
