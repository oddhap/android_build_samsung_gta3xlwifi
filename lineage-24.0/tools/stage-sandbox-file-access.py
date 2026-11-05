#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Narrow old direct file access to Android17 sandbox and app-data boundaries.

Retains read/FD permissions where allowed, removes isolated direct open, limits
tombstone access to read/getattr, and retires direct APK directory mutation.
No attribute, label, assertion or MLS constraint changes. Offline proposal only.
"""
import argparse, hashlib, importlib.util, json
from pathlib import Path

CHANGES = [
 ('(allow isolated_app_30_0 shell_data_file_30_0 (file (ioctl read getattr lock map open watch watch_reads)))',
  '(allow isolated_app_30_0 shell_data_file_30_0 (file (ioctl read getattr lock map watch watch_reads)))',
  'Android17 isolated_app_all.te:59 prohibits direct app-data open; retain FD operations.'),
 ('(allow platform_app_30_0 tombstone_data_file_30_0 (file (ioctl read getattr lock map open watch watch_reads)))',
  '(allow platform_app_30_0 tombstone_data_file_30_0 (file (read getattr)))',
  'Android17 app.te:883 permits only read/getattr for these tombstone clients.'),
 ('(allow system_app_30_0 apk_data_file_30_0 (dir (write add_name remove_name)))', '',
  'Android17 app.te:695 prohibits direct APK writes; installation requires framework mediation.'),
]
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.baseline.read_text())
paths=[Path(x['path']) for x in base['inputs'] if Path(x['path']).name=='vendor_sepolicy.cil'];assert len(paths)==1
src=paths[0];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(src)=='51cb70c0926631d98894360aa8314ff4e2d5f395de1cd9964125036e6a781b18'
for x in base['inputs']:assert sha(Path(x['path']))==x['sha256']
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(src.parent) and not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')
original=src.read_text();staged=original
for before,after,reason in CHANGES:
 assert staged.splitlines().count(before)==1
 if after:
  old=[t[1] for t in cil.tokens(before)];new=[t[1] for t in cil.tokens(after)]
  assert old[:7]==new[:7] and set(new[7:-3])<set(old[7:-3])
 staged=staged.replace(before+'\n',after+'\n')
oldforms=[original[s:e] for _,s,e in forms.statements(original,cil.tokens)]
newforms=[staged[s:e] for _,s,e in forms.statements(staged,cil.tokens)]
replacements={b:n for b,n,_ in CHANGES}
assert [replacements.get(f,f) for f in oldforms if replacements.get(f,f)]==newforms
before,after=cil.rule_counts(original),cil.rule_counts(staged);assert after==dict(before,allow=before['allow']-1)
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged)
report={'scope':__doc__,'changes':[{'before':b,'after':n,'reason':r} for b,n,r in CHANGES],
 'unchanged_retained_statements_byte_exact':True,'source_target_class_unchanged_for_permission_replacements':True,
 'allow_permissions_added':False,'attributes_labels_or_constraints_modified':False,
 'vendor_rules_before':before,'vendor_rules_after':after,'runner_sha256':sha(Path(__file__)),
 'input_vendor_sha256':sha(src),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
 'runtime_validated':False,'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');assert src.read_text()==original
print('STAGED: two permission subsets and one removed APK mutation grant')
