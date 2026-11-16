#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply an earlier actual VINTF result only after exact equality of every factory input.

Does not simulate activation or rerun checkvintf. Unchanged factory APEX bytes,
framework metadata, actual vendor metadata, host tools and kernel config are
mandatory. A changed input fails this check and requires a fresh real run.
"""
import argparse,hashlib,json,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','archive','baseline','geometry','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
r=json.loads(a.baseline.read_text());g=json.loads(a.geometry.read_text());assert r['offline_metadata_passed'] and r['exit_code']==0 and g['artifact_checks_passed']
assert sha(a.archive)==g['archive_sha256'];host=a.top/'out/host/linux-x86/bin'
for n,h in r['host_tools_sha256'].items():assert sha(host/n)==h
for x in r['metadata_inputs']:assert sha(Path(x['path']))==x['sha256']
for x in r['vendor_apex_inputs']:assert sha(Path(x['path']))==x['sha256']
checked=[]
with zipfile.ZipFile(a.archive) as z:
 for x in r['factory_inputs']:
  name=x['archive_member'];assert hashlib.sha256(z.read(name)).hexdigest()==x['sha256'],name;checked.append(name)
 props=dict(line.split('=',1) for line in z.read('SYSTEM/build.prop').decode().splitlines() if '=' in line and not line.startswith('#'))
 vendor_maps=[r['checkvintf_command'][i+1].split(':',1)[1] for i,x in enumerate(r['checkvintf_command'][:-1]) if x=='--dirmap' and r['checkvintf_command'][i+1].startswith('/vendor:')]
 assert len(vendor_maps)==1
 vendor_prop=Path(vendor_maps[0])/'build.prop'
 vprops=dict(line.split('=',1) for line in vendor_prop.read_text().splitlines() if '=' in line and not line.startswith('#'))
 first_api=[v for v in [props.get('ro.product.first_api_level'),vprops.get('ro.product.first_api_level')] if v is not None]
 assert first_api and set(first_api)=={'28'}
record={'passed':True,'scope':__doc__,'method':'prior genuine checkvintf/39-factory-APEX result, all complete inputs unchanged','baseline_report_sha256':sha(a.baseline),'current_archive_sha256':g['archive_sha256'],'factory_input_count':len(checked),'checked_members':checked,'factory_apex_count':r['factory_apex_count'],'actual_vendor_build_prop_sha256':sha(vendor_prop),'first_api_level':first_api,'live_activation_or_FBE_proven':False,'flash_ready':False}
a.output.write_text(json.dumps(record,indent=2)+'\n');print('PASS VINTF evidence applicability:',len(checked),'identical factory inputs')
