#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Classify actual Samsung seapp private data labels as Android17 app data.

Only the required three existing private types gain app_data_file_type. All
existing policy records, labels, grants and assertions remain byte-exact.
Strict compiler and context checks remain mandatory; this is not boot proof.
"""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.baseline.read_text());assert base['passed_strict']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for x in base['inputs']:assert sha(Path(x['path']))==x['sha256']
paths=[Path(x['path']) for x in base['inputs'] if Path(x['path']).name=='vendor_sepolicy.cil'];assert len(paths)==1
src=paths[0];before=src.read_text();context=Path('/srv/android/artifacts/lineage-24.0-arm64/staged-debug-policy-20261105-03/metadata/vendor/etc/selinux/vendor_seapp_contexts')
types=set()
for line in context.read_text().splitlines():
 for field in line.split():
  if field.startswith('type='):types.add(field[5:])
selected=sorted(types-{'app_data_file','system_app_data_file'})
assert selected==['aasa_service_app_data_file','attiqi_app_data_file','policyloader_app_data_file']
for name in selected:assert before.splitlines().count('(type '+name+')')==1
addition='\n(typeattributeset app_data_file_type ('+' '.join(selected)+'))\n'
assert not a.output.exists() and not a.output.resolve().is_relative_to(Path('/srv/android/src'))
a.output.mkdir();dest=a.output/'vendor_sepolicy.cil';dest.write_text(before+addition)
report={'scope':__doc__,'baseline_report_sha256':sha(a.baseline),'original_vendor_cil_sha256':sha(src),'seapp_context_sha256':sha(context),'required_private_app_data_types':selected,'added_statements':[addition.strip()],'original_statements_byte_exact':True,'staged_vendor_cil_sha256':sha(dest),'new_allow_statements':0,'removed_assertions':0,'hardware_tested':False,'flash_ready':False}
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('STAGED 3 existing Samsung app data labels with required app_data_file_type')
