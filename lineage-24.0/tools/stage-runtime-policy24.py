#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Append exact runtime-image control ioctl grants to explicitly selected strict lease inputs.

Preserves the Android17 platform and Samsung vendor assertion inventory and
legacy vendor symbols. Does not select any policy/image inputs automatically.
"""
import argparse,hashlib,importlib.util,json,re,shutil
from collections import Counter
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','kernel','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=json.loads(a.baseline.read_text());assert base['passed_strict'] and base['results'][0]['neverallow_checks_enabled'] and '-N' not in base['results'][0]['command']
inputs={Path(x['path']):x['sha256'] for x in base['inputs']}
for f,h in inputs.items():assert sha(f)==h
platform=next(x for x in inputs if x.name=='plat_sepolicy.cil');before=platform.read_text();assert '(type gta3xlwifi_netpolicy_device)' in before
assert '(allowx netd gta3xlwifi_netpolicy_device (ioctl chr_file ((range 0x6750 0x6753))))' in before
header=a.kernel/'include/uapi/linux/netfilter/gta3xlwifi_runtime_policy.h';text=header.read_text()
for name,number in [('GET','60'),('SET','61')]:
 assert re.search(r"#define GTA3XLWIFI_RUNTIME_"+name+r"\s+_IOW?R?\('g',0x"+number+r"\b",text)
assert '(allowx netd gta3xlwifi_netpolicy_device (ioctl chr_file (0x6757 0x6758)))' in before
assert '(allowx netd gta3xlwifi_netpolicy_device (ioctl chr_file (0x6759)))' in before
assert '(allowx netd gta3xlwifi_netpolicy_device (ioctl chr_file (0x675a)))' in before
assert '(allowx netd gta3xlwifi_netpolicy_device (ioctl chr_file (0x675b 0x675c 0x675d 0x675e 0x675f)))' in before
addition='\n; Exact leased runtime GET/SET, not networking readiness.\n(allowx netd gta3xlwifi_netpolicy_device (ioctl chr_file (0x6760 0x6761)))\n'
assert addition not in before
O.mkdir(parents=True);(O/'plat_sepolicy.cil').write_text(before+addition)
metadata=a.baseline.parent.parent/'metadata'
for name in ['file_contexts','genfs_contexts','ueventd.rc']:
 source=metadata/name;inputs[source]=sha(source);shutil.copyfile(source,O/name)
te=metadata/'gta3xlwifi_netpolicy.te';inputs[te]=sha(te)
(O/te.name).write_text(te.read_text()+'\n# Exact leased runtime controls; device remains root/read-only.\nallowxperm netd gta3xlwifi_netpolicy_device:chr_file ioctl { 0x6760 0x6761 };\n')
def load(n):
 spec=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port');kinds={'neverallow','neverallowx','neverallowxperm','constrain','mlsconstrain','validatetrans','mlsvalidatetrans'}
def inventory(replace=False):
 result=Counter()
 for f in [Path(x['path']) for x in base['inputs']]:
  text=before+addition if replace and f==platform else f.read_text()
  for kind,start,end in forms.statements(text,cil.tokens):
   if kind in kinds:result[' '.join(t[1] for t in cil.tokens(text[start:end]))]+=1
 return result
old,new=inventory(),inventory(True);assert old==new and old
inputs.update({header:sha(header),a.baseline:sha(a.baseline),Path(__file__):sha(Path(__file__))})
for f,h in inputs.items():assert sha(f)==h
(O/'report.json').write_text(json.dumps({'staged':True,'scope':__doc__,'baseline':str(a.baseline),'platform_original_prefix_unchanged':True,'platform_candidate_sha256':sha(O/'plat_sepolicy.cil'),'assertion_constraint_records_preserved':sum(old.values()),'assertion_inventory_sha256':hashlib.sha256(json.dumps(sorted(old.items())).encode()).hexdigest(),'new_ioctl_low16_codes':list(range(0x6760,0x6762)),'inputs_sha256':{str(f):h for f,h in inputs.items()},'active_policy_or_images_changed':False,'flash_ready':False},indent=2)+'\n');print('STAGED: two exact runtime-image ioctls;',sum(old.values()),'assertion/constraint records unchanged')
