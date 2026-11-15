#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile actual complete NetworkStats consumer/journal/clients against original Connectivity SDK classes."""
import argparse,fcntl,hashlib,json,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads(a.native_report.read_text());assert r['passed'] and r['eleven_AIDL_ordinals_verified'];inputs={str(a.native_report.resolve()):sha(a.native_report),str(Path(__file__).resolve()):sha(Path(__file__))}
for n,h in r['inputs_sha256'].items():assert sha(Path(n))==h
cmd=next(c.copy() for c in r['commands'] if c[0].endswith('/javac'));old=next(Path(x).parents[4] for x in cmd if x.endswith('/java/com/android/server/Gta3xlwifiNetpolicyClient.java'))
for path in S.rglob('*'):
 if path.is_file():
  relative=path.relative_to(S);inputs[str(path)]=sha(path)
  if relative.parts[0]!='java':assert sha(old/relative)==sha(path),'Changed native prerequisite '+str(relative)
cmd=[x.replace(str(old/'java'),str(S/'java')) for x in cmd];cmd[cmd.index('-d')+1]=str(O/'classes')
for f in (S/'java').rglob('*.java'):
 if str(f) not in cmd:cmd.append(str(f))
for entry in cmd:
 path=Path(entry)
 if ':' not in entry and len(entry)<4096 and path.is_file():inputs[str(path)]=sha(path)
for entry in cmd[cmd.index('-classpath')+1].split(':'):inputs[entry]=sha(Path(entry))
audit=Path(__file__).with_name('audit-port.py');inputs[str(audit)]=sha(audit)
def check(n):subprocess.run([sys.executable,str(audit),str(T),str(a.snapshot),str(O/(n+'.json'))],check=True,capture_output=True)
check('source-before')
try:
 x=subprocess.run(cmd,cwd=T,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
 for n,h in inputs.items():assert sha(Path(n))==h
 check('source-after');(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'inputs_sha256':inputs,'command':cmd,'native_prerequisites_exactly_unchanged':True,'original_Connectivity_classpaths':True,'actual_Java_source_count':len(list((S/'java').rglob('*.java'))),'actual_complete_consumer_compiled':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual stats clients and unchanged11-RPC native proof; source audits passed')
finally:
 if not (O/'source-after.json').exists():check('source-after')
