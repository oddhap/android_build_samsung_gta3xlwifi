#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the immutable-root cpuacct directory to the actual legacy controller contract."""
import argparse,hashlib,json,stat,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['archive','geometry','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();h=hashlib.sha256()
with a.archive.open('rb') as f:
 for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and h.hexdigest()==g['archive_sha256']
with zipfile.ZipFile(a.archive) as z:
 i=z.getinfo('ROOT/acct/');assert stat.S_ISDIR(i.external_attr>>16) and not (i.external_attr>>16)&0o002
 c=json.loads(z.read('SYSTEM/etc/cgroups.gta3xlwifi.json'));cpu=[x for x in c['Cgroups'] if x['Controller']=='cpuacct'];assert len(cpu)==1 and cpu[0]=={'Controller':'cpuacct','Path':'/acct','Mode':'0775','UID':'system','GID':'system'}
 assert z.read('ROOT/init')==b'/system/bin/gta3xlwifi_first_stage_init'
r={'passed':True,'scope':__doc__,'archive_sha256':h.hexdigest(),'root_acct_directory_present':True,'root_acct_not_world_writable':True,'real_cpuacct_descriptor':cpu[0],'source_mount_operation_unchanged':True,'device_cgroup_mount_proven':False,'flash_ready':False};a.output.write_text(json.dumps(r,indent=2)+'\n');print('PASS actual immutable-root cpuacct mountpoint and descriptor')
