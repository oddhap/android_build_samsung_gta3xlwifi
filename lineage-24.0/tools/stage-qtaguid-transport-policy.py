#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage explicit, minimal SELinux access for the private netd qtaguid transport.

This is isolated source/metadata, never an automatic policy/image selection.
Retains every current-platform/vendor assertion and all original input bytes.
Does not authorize callers, implement networking or claim runtime readiness.
"""
import argparse,hashlib,importlib.util,json,re
from collections import Counter
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','kernel','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'));base=json.loads(a.baseline.read_text());assert base['passed_strict']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={Path(x['path']):x['sha256'] for x in base['inputs']}
for path,h in inputs.items():assert sha(path)==h
platform=next(path for path in inputs if path.name=='plat_sepolicy.cil');vendor=next(path for path in inputs if path.name=='vendor_sepolicy.cil');before=platform.read_text();name='sysfs_gta3xlwifi_qtaguid';assert name not in before
qtaguid=a.kernel/'net/netfilter/xt_qtaguid.c';q=qtaguid.read_text();header=a.kernel/'include/uapi/linux/netfilter/xt_qtaguid_sock.h';h=header.read_text()
assert re.search(r'^#define QTU_DEV_NAME\s+"xt_qtaguid"',q,re.M) and re.search(r'\.name\s*=\s*QTU_DEV_NAME',q)
for param in ['passive','tag_tracking_passive']:assert re.search(r'module_param_named\(\s*'+param+r'\s*,',q)
assert "#define QTAGUID_SOCKET_OWNED_SESSION _IO('q', 0x51)" in h
paths=['/devices/virtual/misc/xt_qtaguid/dev','/module/xt_qtaguid/parameters/passive','/module/xt_qtaguid/parameters/tag_tracking_passive']
for path in paths:assert not re.search(r'\(genfscon sysfs "?'+re.escape(path)+r'"?\s',before)
te='''# SPDX-License-Identifier: Apache-2.0
# The private netd-owned qtaguid I/O session; caller authorization is separate.
type sysfs_gta3xlwifi_qtaguid, fs_type, sysfs_type;
allow netd proc_qtaguid_ctrl:file { open write getattr };
allow netd qtaguid_device:chr_file { open read getattr ioctl };
allowxperm netd qtaguid_device:chr_file ioctl { 0x7151 };
allow netd sysfs_gta3xlwifi_qtaguid:file { open read getattr };
'''
genfs='# SPDX-License-Identifier: Apache-2.0\n'+''.join('genfscon sysfs '+path+' u:object_r:'+name+':s0\n' for path in paths)
addition='\n; Explicit isolated netd qtaguid transport access proposal.\n'+f'''(type {name})
(roletype object_r {name})
(typeattributeset fs_type ({name}))
(typeattributeset sysfs_type ({name}))
(allow netd proc_qtaguid_ctrl (file (open write getattr)))
(allow netd qtaguid_device (chr_file (open read getattr ioctl)))
(allowx netd qtaguid_device (ioctl chr_file (0x7151)))
(allow netd {name} (file (open read getattr)))
'''+''.join('(genfscon sysfs "'+path+'" (u object_r '+name+' ((s0) (s0))))\n' for path in paths)
O.mkdir(parents=True);(O/'plat_sepolicy.cil').write_text(before+addition);(O/'gta3xlwifi_qtaguid_transport.te').write_text(te);(O/'genfs_contexts').write_text(genfs)
# Append-only preserves all previous statements exactly. Also inventory every
# assertion/constraint token record, including xperm and MLS forms.
def load(n):
 spec=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port');checks={'neverallow','neverallowx','neverallowxperm','constrain','mlsconstrain','validatetrans','mlsvalidatetrans'}
def inventory(replace=False):
 counts=Counter()
 for path in inputs:
  text=(before+addition) if replace and path==platform else path.read_text()
  for kind,start,end in forms.statements(text,cil.tokens):
   if kind in checks:counts[' '.join(t[1] for t in cil.tokens(text[start:end]))]+=1
 return counts
old,new=inventory(),inventory(True);assert old==new and old
extra={p:sha(p) for p in [a.baseline,qtaguid,header,Path(__file__)]}
(O/'report.json').write_text(json.dumps({'scope':__doc__,'baseline':str(a.baseline),'baseline_passed_strict':True,'platform_input':str(platform),'vendor_input_unchanged':{'path':str(vendor),'sha256':sha(vendor)},'platform_before_sha256':inputs[platform],'platform_candidate_sha256':sha(O/'plat_sepolicy.cil'),'assertion_constraint_records_preserved':sum(old.values()),'assertion_inventory_sha256':hashlib.sha256(json.dumps(sorted(old.items())).encode()).hexdigest(),'original_platform_prefix_byte_identical':True,'new_sysfs_paths':paths,'new_ioctl':0x7151,'inputs_sha256':{str(p):v for p,v in {**inputs,**extra}.items()},'active_policy_or_images_changed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n')
for path,h in {**inputs,**extra}.items():assert sha(path)==h
print('STAGED: exact netd transport access, three sysfs files and ioctl0x7151; '+str(sum(old.values()))+' assertion/constraint records unchanged')
