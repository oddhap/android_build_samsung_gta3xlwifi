#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Isolated namespace separation plus removal of one forbidden capability grant.

No neverallow assertion or preserved vendor/image/signing material is changed.
Only explicitly enumerated text metadata is read/copied by the parent stager.
"""
import argparse,difflib,hashlib,importlib.util,json
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','vendor','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();spec=importlib.util.spec_from_file_location('ns',Path(__file__).with_name('stage-vendor-uwb-namespace.py'));ns=importlib.util.module_from_spec(spec);spec.loader.exec_module(ns)
removed='(allow system_server_30_0 system_server_30_0 (capability (sys_module)))\n'
original=a.vendor/'etc/selinux/vendor_sepolicy.cil';data=original.read_text();assert data.count(removed)==1
report=ns.stage(a.top,a.vendor,a.output,'8df663eb65a807e6ee99f8b2384cb52d34c994a25087410486b1f88e278e2e53')
f=a.output/'vendor/etc/selinux/vendor_sepolicy.cil';before=f.read_text();assert before.count(removed)==1;after=before.replace(removed,'',1)
x=ns.rule_counts(before);y=ns.rule_counts(after);assert y==dict(x,allow=x['allow']-1)
inverse,_=ns.rewrite_cil(after,{v:k for k,v in ns.RENAMES.items()});assert inverse==data.replace(removed,'',1)
f.write_text(after)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
patch=''
for name in report['changed_files']:
 src=a.vendor/'etc/selinux'/name;dest=a.output/'vendor/etc/selinux'/name
 patch+=''.join(difflib.unified_diff(src.read_text().splitlines(True),dest.read_text().splitlines(True),fromfile='a/etc/selinux/'+name,tofile='b/etc/selinux/'+name))
(a.output/'metadata.patch').write_text(patch)
summary={'scope':__doc__,'removed_exact_allow':removed.strip(),'base_namespace_report_sha256':sha(a.output/'report.json') if (a.output/'report.json').exists() else None,'rule_counts_before':ns.rule_counts(data),'rule_counts_after':y,'no_neverallow_or_xperm_assertion_removed':True,'inverse_except_removed_grant_is_byte_exact':True,'endpoint_name_preserved':ns.ENDPOINT,'source_policy_sha256':sha(original),'staged_policy_sha256':sha(f),'parent_stager_sha256':sha(Path(__file__).with_name('stage-vendor-uwb-namespace.py')),'runner_sha256':sha(Path(__file__)),'metadata_patch_sha256':sha(a.output/'metadata.patch'),'source_unchanged':original.read_text()==data,'security_approved':False,'flash_ready':False}
(a.output/'tightening-report.json').write_text(json.dumps(summary,indent=2)+'\n');print('STAGED: private namespace separation and exactly one removed capability allow; all neverallows retained')
