#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicitly select the audited kernel/vendor pair, retaining immutable rollback copies.

Requires fresh source-built strict policy/context/assertion proofs and complete
vendor image equality checks. No device operations, recovery changes or signing.
"""
import argparse,fcntl,hashlib,json,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','snapshot','vendor-composition','policy-proof','assertions','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
A=Path('/srv/android/artifacts/lineage-24.0-arm64');K=A/'kernel-uid-receipt-build-20261115-01';V=a.vendor_composition.resolve();P=a.policy_proof.resolve()
def report(f):return json.loads(f.read_text())
k=report(K/'report.json');assert k['passed'] and k['actual_Image_all_modules_and_Gator_built'] and k['complete_source_protected_baseline_Android_audits']
image=K/'Image';assert sha(image)=='7ece8d6fd70870811abfe5fd9f947311506f97233491b4016cde441de3578aec'
v=report(V/'report.json');assert v['passed'] and v['all_other_contents_and_security_metadata_identical'] and v['original_vendor_unchanged'] and not v['android_input_selected'];assert v['raw_bytes']==343932928
vendor=V/'vendor.img';assert sha(vendor)==v['vendor_sparse_sha256']
strict=P/'strict/report.json';r=report(strict);assert r['passed_strict'] and not r['explicit_input_overrides'] and r['results'][0]['neverallow_checks_enabled'] and '-N' not in r['results'][0]['command']
assert sha(strict)==v['strict_report_sha256']
for x in r['inputs']:assert sha(Path(x['path']))==x['sha256']
ctx=report(P/'contexts/report.json');assert ctx['passed'] and ctx['inputs_sha256'][str(strict)]==sha(strict)
for name,h in ctx['inputs_sha256'].items():assert sha(Path(name))==h
assertion=report(a.assertions);assert assertion['passed'] and assertion['candidate_report_sha256']==sha(strict) and not assertion['permissive_domains']
B=T/'device/samsung/gta3xlwifi/prebuilt';old={'Image':'33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553','vendor.img':'a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a','dtbo.img':'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b'}
assert {n:sha(B/n) for n in old}==old
O.mkdir(parents=True);audit=Path(__file__).with_name('audit-port.py')
subprocess.run([sys.executable,str(audit),str(T),str(a.snapshot),str(O/'source-before.json')],check=True)
backup=O/'original-prebuilts';backup.mkdir()
for n in old:shutil.copyfile(B/n,backup/n);assert sha(backup/n)==old[n]
selection={'scope':__doc__,'source_snapshot':str(a.snapshot),'before':old,'after':{'Image':sha(image),'vendor.img':sha(vendor),'dtbo.img':old['dtbo.img']},'proofs_sha256':{str(f):sha(f) for f in [K/'report.json',V/'report.json',strict,P/'contexts/report.json',a.assertions]},'flash_ready':False}
(O/'selection.json').write_text(json.dumps(selection,indent=2)+'\n')
# All proofs, complete source audit and original rollback bytes precede mutation.
for src,name in [(image,'Image'),(vendor,'vendor.img')]:
 temp=B/(name+'.selected.tmp');assert not temp.exists();shutil.copyfile(src,temp);assert sha(temp)==selection['after'][name];temp.replace(B/name)
assert {n:sha(B/n) for n in old}==selection['after']
subprocess.run([sys.executable,str(audit),str(T),str(a.snapshot),str(O/'source-after.json')],check=True)
(O/'report.json').write_text(json.dumps({'passed':True,**selection,'original_rollback_copies_verified':True,'hardware_tested':False},indent=2)+'\n');print('Selected coordinated audited kernel/vendor pair; original bytes retained')
