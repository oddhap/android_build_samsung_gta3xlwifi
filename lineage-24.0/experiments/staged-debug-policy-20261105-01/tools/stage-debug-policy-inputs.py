#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare reviewed userdebug inputs from the strict production vendor proposal.

Only the three unavailable-kernel Health BPF grants and default su permissive
declaration are removed from raw userdebug platform CIL. Reuses the reviewed MLS
compatibility retirement after proving its raw input is identical. No source,
image, cache hash or device modification; all current assertions stay intact.
"""
import argparse,hashlib,importlib.util,json
from pathlib import Path
def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')
p=argparse.ArgumentParser(description=__doc__)
for n in ['production-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.production_report.read_text());assert base['passed_strict']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for x in base['inputs']:assert sha(Path(x['path']))==x['sha256']
top=Path('/srv/android/src/lineage-24.0-arm64');art=Path('/srv/android/artifacts/lineage-24.0-arm64')
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(top)
parent=art/'platform-policy-port-20261105-03/metadata/vendor/etc/selinux'
originals={n:(parent/n).read_bytes() for n in cil.FILES}
for name in ['vendor_sepolicy.cil','plat_pub_versioned.cil']:
 matches=[Path(x['path']) for x in base['inputs'] if Path(x['path']).name==name];assert len(matches)==1
 originals[name]=matches[0].read_bytes()
rawplat=top/'out/target/product/gta3xlwifi/system/etc/selinux/plat_sepolicy.cil'
rawcompat=top/'out/target/product/gta3xlwifi/system/etc/selinux/mapping/30.0.compat.cil'
assert sha(rawcompat)=='2b40198379e1bb65ca2af156b25562381273144d94c5ae223b5ed9905d7437cc'
compat=art/'legacy-policy-access-20261105-03/metadata/30.0.compat.cil'
assert str(compat) in {x['path'] for x in base['inputs']}
removed=['(allow hal_health_server fs_bpf_vendor (dir (search)))',
 '(allow hal_health_server fs_bpf_vendor (file (read)))',
 '(allow hal_health_server bpfloader (bpf (prog_run)))','(typepermissive su)']
before=rawplat.read_text();after=before
for statement in removed:
 assert after.splitlines().count(statement)==1,statement
 after=after.replace(statement+'\n','\n')
def statements(text):return [text[s:e] for _,s,e in forms.statements(text,cil.tokens)]
assert [s for s in statements(before) if s not in removed]==statements(after)
oldcompat=statements(rawcompat.read_text());newcompat=statements(compat.read_text())
mls=[s for s in oldcompat if s.startswith('(typeattributeset mlsvendorcompat ') or s.startswith('(allow mlsvendorcompat ')]
assert len(mls)==5 and [s for s in oldcompat if s not in mls]==newcompat
out.mkdir(parents=True);dest=out/'vendor/etc/selinux';dest.mkdir(parents=True)
for name,data in originals.items():
 assert len(data)<16*1024*1024 and b'\x00' not in data;data.decode();(dest/name).write_bytes(data)
if (parent/'genfs_labels_version.txt').exists():(dest/'genfs_labels_version.txt').write_bytes((parent/'genfs_labels_version.txt').read_bytes())
(out/'plat_sepolicy.cil').write_text(after);(out/'30.0.compat.cil').write_bytes(compat.read_bytes())
report={'scope':__doc__,'production_policy_passed_strict':True,'production_report_sha256':sha(a.production_report),
 'removed_userdebug_statements':removed,'all_retained_userdebug_statements_byte_exact':True,
 'removed_compat_statements':mls,'all_retained_compat_statements_byte_exact':True,
 'permissive_domains_added':False,'removed_default_permissive_domain':'su',
 'original_input_sha256':{str(rawplat):sha(rawplat),str(rawcompat):sha(rawcompat),str(compat):sha(compat)},
 'staged_text_sha256':{str(p.relative_to(out)):sha(p) for p in [out/'plat_sepolicy.cil',out/'30.0.compat.cil',*dest.iterdir()]},
 'runner_sha256':sha(Path(__file__)),'runtime_validated':False,'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('STAGED userdebug: current assertions retained, no permissive domains added; su made enforcing')
