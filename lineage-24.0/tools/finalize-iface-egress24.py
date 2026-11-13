#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finalize immutable Image/module evidence with an explicit Module.symvers transition.

The initial Image and module jobs stopped on incorrect test assumptions, not
compilation. Keep those exits. Verify every frozen input and the actual expected
module-export extension with the strict module CRC checker; never waive a hash.
"""
import argparse,fcntl,hashlib,json,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['base','initial','completion','protected','top','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(a.top.resolve());mutex=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(mutex,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(p):inputs[str(p.resolve())]=sha(p)
T=Path(__file__).resolve().parent;bind(Path(__file__));src=a.base/'src';out=a.base/'out';r=json.loads((a.completion/'resume-provenance.json').read_text());bind(a.completion/'resume-provenance.json');sym=out/'Module.symvers';before=a.completion/'vmlinux-Module.symvers-before';module=json.loads((a.completion/'module-versions.json').read_text());bind(a.completion/'module-versions.json')
assert module['passed'] and module['total_exports_after']>module['vmlinux_exports_retained']
assert sha(before)==r['inputs_sha256'][str(sym)]
assert sha(sym)==module['inputs_sha256'][str(sym)]
for path,h in r['inputs_sha256'].items():
 if path==str(sym):continue # Checked BOTH exact endpoints above; CRC checker below proves the transition.
 assert sha(Path(path))==h,'Frozen input changed: '+path
 bind(Path(path))
bind(before);bind(sym)
checker=T.parent/'experiments/kernel-gator-20261105-01/check-module-versions.py';bind(checker)
subprocess.run([sys.executable,str(checker),str(a.base),str(a.completion),str(O/'module-versions.json')],check=True)
for prefix,path in [('source',src),('protected',a.protected)]:
 tool=T/'audit-kernel-tree.py';bind(tool);subprocess.run([sys.executable,str(tool),str(path),str(O/(prefix+'-current.json'))],check=True)
 values=[]
 for directory,moments in [(a.initial,['before','after']),(a.completion,['before','after']),(O,['current'])]:
  for moment in moments:
   q=directory/(prefix+'-'+moment+'.json');bind(q);values.append(json.loads(q.read_text()))
 for key in ['revision','tree','tracked_sha256','diff_sha256']:assert all(v[key]==values[0][key] for v in values),(prefix,key)
tool=T/'audit-port.py';bind(tool);subprocess.run([sys.executable,str(tool),str(a.top),str(a.snapshot),str(O/'android-source-current.json')],check=True)
reloc=a.completion/'output-relocations/report.json';rr=json.loads(reloc.read_text());assert rr['passed'] and all(x['entire_normalized_disassembly_identical'] for x in rr['output_objects']);bind(reloc)
for path,h in rr['inputs_sha256'].items():assert sha(Path(path))==h;bind(Path(path))
for row in module['modules']:assert sha(Path(row['path']))==row['sha256'];bind(Path(row['path']))
assert sha(out/'arch/arm64/boot/Image')==(a.completion/'Image-before.sha256').read_text().split()[0]
assert sha(out/'.config')==sha(a.completion/'kernel.config-before')
selected={}
for name,h in {'Image':'33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553','vendor.img':'a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a','dtbo.img':'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b'}.items():
 q=a.top/'device/samsung/gta3xlwifi/prebuilt'/name;assert sha(q)==h;selected[name]=h;bind(q)
for path,h in inputs.items():assert sha(Path(path))==h
shutil.copyfile(out/'arch/arm64/boot/Image',O/'Image');shutil.copyfile(out/'.config',O/'kernel.config')
(O/'SHA256SUMS').write_text(sha(O/'Image')+'  '+str(O/'Image')+'\n'+sha(O/'kernel.config')+'  '+str(O/'kernel.config')+'\n')
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'image_sha256':sha(O/'Image'),'config_sha256':sha(O/'kernel.config'),'initial_image_job_exit_preserved':1,'module_job_exit_preserved':1,'expected_module_symvers_transition':{'before_sha256':sha(before),'after_sha256':sha(sym),'vmlinux_exports_retained':module['vmlinux_exports_retained'],'total_exports_after':module['total_exports_after']},'all_frozen_resume_inputs_verified':True,'source_and_protected_audits_identical_across_all_stages':True,'normalized_output_machine_code_verified':True,'selected_inputs_unchanged':selected,'inputs_sha256':inputs,'android_prebuilt_promoted':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: Image/modules/source/relocations and exact expected export transition; original failed job exits retained')
