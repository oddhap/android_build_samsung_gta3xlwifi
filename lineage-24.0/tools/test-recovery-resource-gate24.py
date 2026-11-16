#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual recovery-resource validation bodies with explicit ZIP metadata fixtures."""
import argparse,ast,hashlib,json,types
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
class ExternalError(Exception):pass
class Zip:
 def __init__(self,names):self.names=names
 def namelist(self):return self.names
names={'ValidateRecoveryResources','HasRecoveryPatch'};tree=ast.parse(a.source.read_text());functions=[x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name in names];assert len(functions)==2
env={'common':types.SimpleNamespace(ExternalError=ExternalError)};exec(compile(ast.Module(body=functions,type_ignores=[]),str(a.source),'exec'),env)
run=env['ValidateRecoveryResources'];cases=[]
def check(label,entries,info,device='gta3xlwifi',two_step=False,wipe=False,ok=True):
 try:run(Zip(entries),info,device,two_step,wipe)
 except (AssertionError,ExternalError):assert not ok,label
 else:assert ok,label
 cases.append(label)
for board,prefix in [('true','VENDOR'),('false','SYSTEM/vendor')]:
 for resource in ['recovery-from-boot.p','etc/recovery.img']:
  check('generic existing '+board+resource,[prefix+'/'+resource],{'board_uses_vendorimage':board},device='other_device')
 check('generic missing '+board,[],{'board_uses_vendorimage':board},device='other_device',ok=False)
valid={'gta3xlwifi_preserve_recovery':'true','allow_non_ab':'true'}
check('preserved recovery with no replacement',[],valid)
check('diagnostic target-files recovery image is not an installed resource',['IMAGES/recovery.img'],valid)
for device in ['other_device','gta3xlwifi_bad','']:
 check('wrong preserved device '+device,[],valid,device=device,ok=False)
for k,v in [('allow_non_ab','false'),('allow_non_ab',''),('ab_update','true'),('multistage_support','1'),('multistage_support','0')]:
 check('invalid contract '+k+v,[],{**valid,k:v},ok=False)
check('two step prohibited',[],valid,two_step=True,ok=False);check('data wipe prohibited',[],valid,wipe=True,ok=False)
for prefix in ['SYSTEM/bin','VENDOR/bin','ODM/bin','SYSTEM/vendor/bin']:
 for resource in ['install-recovery.sh','recovery-from-boot.p','recovery-resource.dat','vendor_flash_recovery.rc','etc/recovery.img']:
  check('replacement prohibited '+prefix+'/'+resource,[prefix+'/'+resource],valid,ok=False)
# Generic behavior and the detector must remain honest: absent means absent.
assert env['HasRecoveryPatch'](Zip([]),{})==False
(a.output/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'candidate_source_sha256':hashlib.sha256(a.source.read_bytes()).hexdigest(),'case_count':len(cases),'cases':cases,'image_contents_or_device_validated':False,'flash_ready':False},indent=2)+'\n');print('PASS',len(cases),'recovery resource contract cases')
