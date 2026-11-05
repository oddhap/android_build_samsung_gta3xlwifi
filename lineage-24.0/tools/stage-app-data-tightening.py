#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Remove three old app-private-data grants forbidden by Android17 MLS assertions.

Preserve domain classifications, MLS constraints, labels and every assertion.
Offline source proposal only; no app execution or filesystem validation.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

GRANTS = [
    ('(allow system_app_30_0 privapp_data_file_30_0 (dir (search)))',
     'Android17 mlstrustedsubject.te:52 disallows this privileged app-private directory search.'),
    ('(allow system_server_30_0 app_data_file_30_0 (file (rename)))',
     'Android17 mlstrustedsubject.te:16 forbids privileged renaming of app-private files.'),
    ('(allow attiqi_app app_data_file_30_0 (file (execute)))',
     'Android17 mlstrustedsubject.te:16 forbids an MLS-trusted app executing app-private files.'),
]
p = argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:
    p.add_argument('--'+n,type=Path,required=True)
a = p.parse_args()
base = json.loads(a.baseline.read_text())
vendor = [Path(x['path']) for x in base['inputs'] if Path(x['path']).name=='vendor_sepolicy.cil']
assert len(vendor)==1
vendor = vendor[0]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(vendor)=='599eb37b5cec211f885d9b5f921dae59db42b1841dce4fef8fa641c28c1f5e9c'
for item in base['inputs']:
    assert sha(Path(item['path']))==item['sha256']
out = a.output.resolve()
assert not out.exists() and not out.is_relative_to(vendor.parent) and not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
original = vendor.read_text()
staged = original
for statement,reason in GRANTS:
    assert staged.splitlines().count(statement)==1
    staged=staged.replace(statement+'\n','\n')
spec=importlib.util.spec_from_file_location('cil',Path(__file__).with_name('stage-vendor-uwb-namespace.py'))
cil=importlib.util.module_from_spec(spec)
spec.loader.exec_module(cil)
before,after=cil.rule_counts(original),cil.rule_counts(staged)
assert after==dict(before,allow=before['allow']-3)
out.mkdir(parents=True)
(out/'vendor_sepolicy.cil').write_text(staged)
(out/'report.json').write_text(json.dumps({'scope':__doc__,'removed_grants':[{'statement':s,'reason':r} for s,r in GRANTS],
    'vendor_rule_counts_before':before,'vendor_rule_counts_after':after,
    'attributes_labels_and_constraints_modified':False,'allow_statements_added':False,
    'baseline_report_sha256':sha(a.baseline),'input_vendor_sha256':sha(vendor),
    'runner_sha256':sha(Path(__file__)),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
    'security_approved':False,'flash_ready':False},indent=2)+'\n')
assert vendor.read_text()==original
print('STAGED: three removed app-private-data grants; no label/MLS classification changes')
