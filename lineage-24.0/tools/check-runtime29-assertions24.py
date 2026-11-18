#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify full CIL equality after the compiler renumbers known synthetic attributes."""
from pathlib import Path
import hashlib
import json
import re
import sys

baseline, candidate, literal, output = map(Path,sys.argv[1:])

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

before=json.loads(baseline.read_text())
after=json.loads(candidate.read_text())
raw=json.loads(literal.read_text())
assert raw['baseline_report_sha256']==sha(baseline)
assert raw['candidate_report_sha256']==sha(candidate)
assert raw['baseline_assertions_and_constraints']==raw['candidate_assertions_and_constraints']==5881
assert not raw['permissive_domains'] and len(raw['removed'])==len(raw['added'])==19
for report,path in ((before,baseline),(after,candidate)):
    result=report['results'][0]
    assert report['passed_strict'] and not report['explicit_input_overrides']
    assert result['exit_code']==0 and result['neverallow_checks_enabled']
    assert '-N' not in result['command']
    assert sha(path.parent/'strict.policy')==result['compiled_policy_sha256']
assert len(before['inputs'])==len(after['inputs'])

def normalized(source):
    rule = (b';;* lmx 13 device/samsung/gta3xlwifi/sepolicy/private/gta3xlwifi_ion.te\n'
            b'(allow base_typeattr_1207 ion_device (chr_file (ioctl read getattr map open)))\n'
            b';;* lme\n')
    members = (b'(typeattribute base_typeattr_1207)\n'
               b'(typeattributeset base_typeattr_1207 (and (untrusted_app_all ) (not (runas_app ))))\n')
    for addition in (rule,members):
        assert source.count(addition)==1
        source=source.replace(addition,b'',1)
    assert not re.search(rb'\bbase_typeattr_1207\b',source)
    def undo(match):
        number=int(match[1])
        if 1208<=number<=1226:
            return b'base_typeattr_'+str(number-1).encode('ascii')
        return match[0]
    return re.sub(rb'\bbase_typeattr_(\d+)\b',undo,source)

examined=0
for index,(prior,current) in enumerate(zip(before['inputs'],after['inputs'])):
    prior_path=Path(prior['path'])
    current_path=Path(current['path'])
    assert prior_path.name==str(index)+'-'+current_path.name
    assert sha(prior_path)==prior['sha256'] and sha(current_path)==current['sha256']
    if current_path.name=='system_ext_sepolicy.cil':
        assert normalized(current_path.read_bytes())==prior_path.read_bytes()
        examined+=1
    else:
        assert current['sha256']==prior['sha256']
assert examined==1
assert not output.exists()
output.write_text(json.dumps({
    'passed':True, 'scope':__doc__,
    'baseline_report_sha256':sha(baseline), 'candidate_report_sha256':sha(candidate),
    'literal_inventory_report_sha256':sha(literal),
    'baseline_assertions_and_constraints':5881,'candidate_assertions_and_constraints':5881,
    'permissive_domains':[], 'strict_compilation_unmodified':True,
    'other_input_hashes_equal':True,'full_system_ext_cil_equal_after_alias_renumbering':True,
    'existing_synthetic_attribute_aliases_renumbered':19,
    'added_access':'untrusted_app_all excluding runas_app, ION chr_file getattr/open/read/ioctl/map',
    'hardware_tested':False,'flash_ready':False,
},indent=2)+'\n')
print('PASS byte-exact existing CIL after verified synthetic alias renumbering; 5881 assertions retained')
