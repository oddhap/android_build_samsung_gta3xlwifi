#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Remove the old privileged-app SIOCGIWESSID allowx forbidden by Android17.

The ioctl reads wireless ESSID directly. Android17 requires the framework's
permission-controlled Wi-Fi API instead. No other ioctl grant or assertion,
kernel helper, source/target classification or readiness behavior changes.
"""
import argparse,hashlib,importlib.util,json,re
from pathlib import Path
def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,diagnostics=load('stage-vendor-uwb-namespace'),load('policy-diagnostics')
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.baseline.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
paths=[Path(x['path']) for x in base['inputs'] if Path(x['path']).name=='vendor_sepolicy.cil'];assert len(paths)==1
src=paths[0]
for x in base['inputs']:assert sha(Path(x['path']))==x['sha256']
statement='(allowx priv_app_30_0 self (ioctl udp_socket (0x8b1b)))'
extended=[b for b in diagnostics.blocks(a.baseline.with_name('strict.log').read_text()) if b['kind']=='neverallowx']
assert len(extended)==1 and 'priv_app_all domain (ioctl udp_socket' in extended[0]['assertion'] and statement in extended[0]['body']
header=Path('/srv/android/ports/lineage-24.0-arm64/kernel-capabilities-20261104-01/src/include/uapi/linux/wireless.h')
assert re.search(r'#define\s+SIOCGIWESSID\s+0x8B1B',header.read_text())
original=src.read_text();assert original.splitlines().count(statement)==1
staged=original.replace(statement+'\n','\n');before,after=cil.rule_counts(original),cil.rule_counts(staged)
assert after==dict(before,allowx=before['allowx']-1)
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(src.parent) and not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged)
(out/'report.json').write_text(json.dumps({'scope':__doc__,'removed_allowx':statement,'ioctl':'SIOCGIWESSID','ioctl_value':'0x8b1b',
 'triggering_assertion':extended[0]['assertion'],'vendor_rule_counts_before':before,'vendor_rule_counts_after':after,
 'all_other_text_byte_exact':True,'assertion_or_kernel_changes':False,
 'inputs_sha256':{str(src):sha(src),str(a.baseline):sha(a.baseline),str(header):sha(header)},
 'runner_sha256':sha(Path(__file__)),'staged_vendor_sha256':sha(out/'vendor_sepolicy.cil'),
 'runtime_wifi_app_behavior_tested':False,'security_approved':False,'flash_ready':False},indent=2)+'\n')
assert src.read_text()==original
print('STAGED: forbidden privileged-app ESSID-read ioctl grant removed; all assertions retained')
