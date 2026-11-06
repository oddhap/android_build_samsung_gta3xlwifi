#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage explicit, minimal SELinux access for the private netd packet-barrier lease.

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
platform=next(path for path in inputs if path.name=='plat_sepolicy.cil');vendor=next(path for path in inputs if path.name=='vendor_sepolicy.cil');before=platform.read_text();name='sysfs_gta3xlwifi_netpolicy';assert name not in before
driver=a.kernel/'net/netfilter/gta3xlwifi_netpolicy.c';q=driver.read_text();header=a.kernel/'include/uapi/linux/netfilter/gta3xlwifi_netpolicy.h';h=header.read_text()
assert '.name = "gta3xlwifi_netpolicy"' in q and '.mode = 0400' in q
assert 'ns_capable(&init_user_ns, CAP_NET_ADMIN)' in q and 'GLOBAL_ROOT_UID' in q
for command,number in [('ABI','50'),('HOLD','51'),('RELEASE','52'),('STATE','53')]:
 assert re.search(r'#define GTA3XLWIFI_NETPOLICY_'+command+r"\s+_IO\('g', 0x"+number+r"\)",h)
paths=['/devices/virtual/misc/gta3xlwifi_netpolicy/dev'];device='gta3xlwifi_netpolicy_device'
assert device not in before
for path in paths:assert not re.search(r'\(genfscon sysfs "?'+re.escape(path)+r'"?\s',before)
te='''# SPDX-License-Identifier: Apache-2.0
# Explicit isolated proposal for the exclusively owned packet-barrier lease.
type gta3xlwifi_netpolicy_device, dev_type;
type sysfs_gta3xlwifi_netpolicy, fs_type, sysfs_type;
allow netd gta3xlwifi_netpolicy_device:chr_file { open read getattr ioctl };
allowxperm netd gta3xlwifi_netpolicy_device:chr_file ioctl { 0x6750-0x6753 };
allow netd sysfs_gta3xlwifi_netpolicy:file { open read getattr };
'''
genfs='# SPDX-License-Identifier: Apache-2.0\n'+''.join('genfscon sysfs '+path+' u:object_r:'+name+':s0\n' for path in paths)
addition='\n; Explicit isolated netd packet-barrier lease proposal.\n'+f'''(type {device})
(roletype object_r {device})
(typeattributeset dev_type ({device}))
(type {name})
(roletype object_r {name})
(typeattributeset fs_type ({name}))
(typeattributeset sysfs_type ({name}))
(allow netd {device} (chr_file (open read getattr ioctl)))
(allowx netd {device} (ioctl chr_file ((range 0x6750 0x6753))))
(allow netd {name} (file (open read getattr)))
'''+''.join('(genfscon sysfs "'+path+'" (u object_r '+name+' ((s0) (s0))))\n' for path in paths)
O.mkdir(parents=True);(O/'plat_sepolicy.cil').write_text(before+addition);(O/'gta3xlwifi_netpolicy.te').write_text(te);(O/'genfs_contexts').write_text(genfs)
(O/'file_contexts').write_text('/dev/gta3xlwifi_netpolicy -c u:object_r:'+device+':s0\n')
(O/'ueventd.rc').write_text('/dev/gta3xlwifi_netpolicy 0400 root root\n')
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
extra={p:sha(p) for p in [a.baseline,driver,header,Path(__file__)]}
(O/'report.json').write_text(json.dumps({'scope':__doc__,'baseline':str(a.baseline),'baseline_passed_strict':True,'platform_input':str(platform),'vendor_input_unchanged':{'path':str(vendor),'sha256':sha(vendor)},'platform_before_sha256':inputs[platform],'platform_candidate_sha256':sha(O/'plat_sepolicy.cil'),'assertion_constraint_records_preserved':sum(old.values()),'assertion_inventory_sha256':hashlib.sha256(json.dumps(sorted(old.items())).encode()).hexdigest(),'original_platform_prefix_byte_identical':True,'new_sysfs_paths':paths,'new_ioctls':[0x6750,0x6751,0x6752,0x6753],'inputs_sha256':{str(p):v for p,v in {**inputs,**extra}.items()},'active_policy_or_images_changed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n')
for path,h in {**inputs,**extra}.items():assert sha(path)==h
print('STAGED: explicit netd lease access, exact device/sysfs labels and four private ioctls; '+str(sum(old.values()))+' assertion/constraint records unchanged')
