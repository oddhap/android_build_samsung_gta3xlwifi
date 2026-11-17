#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compose an isolated vendor image from explicitly selected, strictly linked metadata.

The original Lineage 21 MTP vendor image remains immutable. Only the two reviewed
CIL inputs, matching strict precompiled policy/hash sidecars, and a ueventd import
are changed. All other contents and inode security metadata must compare equal.
This does not select Android prebuilts or authorize installation.
"""
import argparse,fcntl,hashlib,json,re,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','strict-report','vendor-metadata','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
R=json.loads(a.strict_report.read_text());assert R['passed_strict'] and not R['explicit_input_overrides'];assert '-N' not in R['results'][0]['command'] and R['results'][0]['neverallow_checks_enabled']
for f in R['inputs']:assert sha(Path(f['path']))==f['sha256']
policy=a.strict_report.parent/'strict.policy';assert sha(policy)==R['results'][0]['compiled_policy_sha256']
V=a.vendor_metadata.resolve();expected={'plat_pub_versioned.cil':'5478939b47a7980cd4abe373a0825d812c8f103f65d9d2dd8883781f39b20a6f','vendor_sepolicy.cil':'7455615956ed1d316bae5b609fa24e759036478117915f497674ab74e170e161'}
for name,h in expected.items():assert sha(V/'etc/selinux'/name)==h and any(x['sha256']==h for x in R['inputs'])
original=Path('/srv/android/artifacts/lineage-24.0-arm64/runtime-input-selection-20261116-01/original-prebuilts/vendor.img');original_sha='a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a';assert sha(original)==original_sha
O.mkdir(parents=True);bin=T/'out/host/linux-x86/bin';raw=O/'original.raw.img'
subprocess.run([str(bin/'simg2img'),str(original),str(raw)],check=True);assert raw.stat().st_size==343932928
image=O/'vendor.raw.img';shutil.copyfile(raw,image)
audit=Path(__file__).with_name('audit-ext4-tree24.py')
def manifest(img,label):
 subprocess.run([sys.executable,str(audit),'--image',str(img),'--output',str(O/label)],check=True)
 return json.loads((O/label/'report.json').read_text())['entries']
before=manifest(raw,'before');staged=O/'staged';staged.mkdir();changes={}
for name in expected:changes['/etc/selinux/'+name]=V/'etc/selinux'/name
changes['/etc/selinux/precompiled_sepolicy']=policy
roots={'plat':T/'out/target/product/gta3xlwifi/system/etc/selinux','system_ext':T/'out/target/product/gta3xlwifi/system/system_ext/etc/selinux','product':T/'out/target/product/gta3xlwifi/product/etc/selinux'}
for part,root in roots.items():
 f=root/(part+'_sepolicy_and_mapping.sha256');assert re.fullmatch(rb'[0-9a-f]{64}\n?',f.read_bytes())
 changes['/etc/selinux/precompiled_sepolicy.'+f.name]=f
# A17 system ueventd imports vendor/etc/ueventd.rc. This explicit import reaches
# the existing Samsung device rules and the exact 0400 root/root lease rule.
assert '/etc/ueventd.rc' not in before,'Review existing vendor rules before composing'
assert '/ueventd.rc' in before and before['/ueventd.rc']['type']=='regular'
ueventd=staged/'ueventd.rc';ueventd.write_text('# Android 17 Samsung device node configuration.\nimport /vendor/ueventd.rc\nimport /ueventd.exynos7904.rc\n');changes['/etc/ueventd.rc']=ueventd
rc=T/'device/samsung/gta3xlwifi/rootdir/ueventd.exynos7904.rc';assert '/dev/gta3xlwifi_netpolicy 0400 root root' in rc.read_text()
commands=[];label=staged/'selinux-label';label.write_bytes(b'u:object_r:vendor_configs_file:s0\0')
for i,(dest,src) in enumerate(changes.items()):
 assert src.is_file() and not any(c in str(src)+dest for c in '\n\r"\\ ')
 if dest in before:
  m=before[dest];assert m['type']=='regular' and m['uid']==0 and m['gid']==0 and m['mode']=='0644'
  assert m['extended_attributes']=='  security.selinux (34) = "u:object_r:vendor_configs_file:s0\\000"',m
  commands.append('rm '+dest)
 commands.extend(['write '+str(src)+' '+dest,'set_inode_field '+dest+' mode 0100644','set_inode_field '+dest+' uid 0','set_inode_field '+dest+' gid 0','ea_set -f '+str(label)+' '+dest+' security.selinux'])
 for stamp in ['atime','ctime','mtime','crtime']:commands.append('set_inode_field '+dest+' '+stamp+' 1230735600')
cmd=O/'compose.commands';cmd.write_text('\n'.join(commands)+'\n')
r=subprocess.run(['debugfs','-w','-f',str(cmd),str(image)],capture_output=True,text=True);(O/'compose.log').write_text(r.stdout+r.stderr);assert r.returncode==0
r=subprocess.run(['e2fsck','-fn',str(image)],capture_output=True,text=True);(O/'e2fsck.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
after=manifest(image,'after');assert set(after)==set(before)|{'/etc/ueventd.rc'}
for path,m in before.items():
 if path not in changes:assert after[path]==m,('Unreviewed vendor difference',path,m,after[path])
 else:
  assert {k:v for k,v in after[path].items() if k not in ['size','sha256']}=={k:v for k,v in m.items() if k not in ['size','sha256']},('Modified security metadata',path)
for dest,src in changes.items():assert after[dest]['sha256']==sha(src)
sparse=O/'vendor.img';subprocess.run([str(bin/'img2simg'),str(image),str(sparse)],check=True)
assert sha(original)==original_sha and image.stat().st_size==343932928
report={'passed':True,'scope':__doc__,'original_vendor_sha256':original_sha,'strict_report_sha256':sha(a.strict_report),'strict_policy_sha256':sha(policy),'vendor_sparse_sha256':sha(sparse),'vendor_raw_sha256':sha(image),'raw_bytes':image.stat().st_size,'entries_before':len(before),'entries_after':len(after),'changed_paths':{dest:sha(src) for dest,src in changes.items()},'all_other_contents_and_security_metadata_identical':True,'original_vendor_unchanged':True,'android_input_selected':False,'hardware_tested':False,'flash_ready':False}
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS isolated vendor composition:',len(changes),'explicit metadata paths')
