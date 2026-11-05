#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Narrow policy permissions for the pinned kernel's absent eBPF syscall/bpffs.

Classic socket BPF remains enabled. No BPF program/loader/backend readiness is
claimed or changed. All assertions remain; this is an isolated device-profile
permission proposal, not a networking implementation or boot approval.
"""
import argparse,hashlib,importlib.util,json,re
from pathlib import Path

def load(n):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')
p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();base=json.loads(a.baseline.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inputs={Path(x['path']):x['sha256'] for x in base['inputs']}
for path,h in inputs.items():assert sha(path)==h
def unique(name):
 paths=[p for p in inputs if p.name==name];assert len(paths)==1;return paths[0]
vendor,platform=unique('vendor_sepolicy.cil'),unique('plat_sepolicy.cil')
assert sha(platform)=='3dc2711ff5e307db50636ac31a4dbf6a79e971220cb7adba2ba6d1351bc9885b'
kernel=Path('/srv/android/ports/lineage-24.0-arm64/kernel-capabilities-20261104-01')
config=kernel/'out/.config';image=kernel/'out/arch/arm64/boot/Image'
assert sha(config)=='fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea'
assert sha(image)=='5d3b21c1a9abb1e7c5175670606f9486c8a5da8f8ad536c132c5bd9c6c350fb2'
cfg=config.read_text().splitlines()
assert 'CONFIG_BPF=y' in cfg and '# CONFIG_BPF_SYSCALL is not set' in cfg and '# CONFIG_BPF_JIT is not set' in cfg
make=kernel/'src/kernel/bpf/Makefile';sysctl=kernel/'src/kernel/sysctl.c';netctl=kernel/'src/net/core/sysctl_net_core.c'
assert 'obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o' in make.read_text()
assert '#ifdef CONFIG_BPF_SYSCALL\n\t{\n\t\t.procname\t= "unprivileged_bpf_disabled"' in sysctl.read_text()
assert re.search(r'#ifdef CONFIG_BPF_JIT\s+\{\s+\.procname\s*=\s*"bpf_jit_enable"',netctl.read_text())
root=Path('/srv/android/artifacts/lineage-24.0-arm64/vendor-check-20261101-01/vendor')
manifest=root/'etc/vintf/manifest/android.hardware.health@2.1-samsung.xml'
rc=root/'etc/init/android.hardware.health@2.1-service-samsung.rc'
binary=root/'bin/hw/android.hardware.health@2.1-service-samsung'
assert '@2.1::IHealth/default' in manifest.read_text()
assert '/vendor/bin/hw/android.hardware.health@2.1-service-samsung' in rc.read_text()
types=set();attrs=set();defs={};texts={p:p.read_text() for p in inputs}
for text in texts.values():
 for kind,s,e in forms.statements(text,cil.tokens):
  ts=cil.tokens(text[s:e])
  if kind=='type':types.add(ts[2][1])
  elif kind=='typeattribute':attrs.add(ts[2][1])
  elif kind=='typeattributeset':defs.setdefault(ts[2][1],[]).append(ts)
def positive(n,trail=()):
 if n in types:return {n}
 assert n in attrs and n not in trail
 out=set()
 for ts in defs.get(n,[]):
  assert ts[3][0]=='(' and ts[-2][0]==')' and all(t[0]=='symbol' and t[1] not in ['and','or','not','all','xor'] for t in ts[4:-2])
  for t in ts[4:-2]:out|=positive(t[1],trail+(n,))
 return out
bpffs=positive('bpffs_type');old_bpf=positive('fs_bpf_30_0');assert old_bpf and old_bpf<=bpffs
out=a.output.resolve();assert not out.exists() and not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
for path in inputs:assert not out.is_relative_to(path.parent)
targets={'base_typeattr_545_30_0':'vendor_samsung_port_nonbpf_fs545',
         'base_typeattr_551_30_0':'vendor_samsung_port_nonbpf_fs551',
         'proc_net_30_0':'vendor_samsung_port_nonbpf_procnet',
         'proc_30_0':'vendor_samsung_port_nonbpf_proc'}
for name in [*targets.values(),'vendor_samsung_port_nonbpffs','vendor_samsung_port_nonbpfproc']:
 for text in texts.values():assert name not in text
drop={
 '(allow system_app_30_0 fs_bpf_30_0 (file (ioctl read getattr lock map open watch watch_reads)))',
 '(allow system_app_30_0 fs_bpf_30_0 (dir (ioctl read getattr lock open watch watch_reads search)))'}
original=texts[vendor];pieces=[];end=0;changes=[];dropped=[]
for kind,start,stop in forms.statements(original,cil.tokens):
 if kind!='allow':continue
 form=original[start:stop];ts=cil.tokens(form)
 if form in drop:
  replacement='';dropped.append(form)
 elif ts[3][1] in targets:
  token=ts[3];replacement=form[:token[2]]+targets[token[1]]+form[token[3]:]
  changes.append({'before':form,'after':replacement})
 else:continue
 pieces.extend([original[end:start],replacement]);end=stop
pieces.append(original[end:]);staged=''.join(pieces)
assert set(dropped)==drop and len(dropped)==2
addition='\n(typeattribute vendor_samsung_port_nonbpffs)\n(typeattributeset vendor_samsung_port_nonbpffs (not bpffs_type))\n'
addition+='(typeattribute vendor_samsung_port_nonbpfproc)\n(typeattributeset vendor_samsung_port_nonbpfproc (not proc_bpf))\n'
for old,new in targets.items():
 exclusion='vendor_samsung_port_nonbpffs' if 'base_typeattr' in old else 'vendor_samsung_port_nonbpfproc'
 addition+=f'(typeattribute {new})\n(typeattributeset {new} (and {old} {exclusion}))\n'
staged+=addition
assert cil.rule_counts(staged)==dict(cil.rule_counts(original),allow=cil.rule_counts(original)['allow']-2)
health=['(allow hal_health_server fs_bpf_vendor (dir (search)))','(allow hal_health_server fs_bpf_vendor (file (read)))','(allow hal_health_server bpfloader (bpf (prog_run)))']
plat=texts[platform]
for statement in health:
 assert plat.splitlines().count(statement)==1;plat=plat.replace(statement+'\n','\n')
assert cil.rule_counts(plat)==dict(cil.rule_counts(texts[platform]),allow=cil.rule_counts(texts[platform])['allow']-3)
out.mkdir(parents=True);(out/'vendor_sepolicy.cil').write_text(staged);(out/'plat_sepolicy.cil').write_text(plat)
(out/'added-target-scopes.cil').write_text(addition)
report={'scope':__doc__,'classic_socket_bpf_enabled':True,'bpf_syscall_jit_and_bpffs_absent_in_pinned_kernel':True,
 'actual_kernel_bpffs_make_guard':make.read_text(),'bpffs_types':sorted(bpffs),'old_bpf_alias_types':sorted(old_bpf),
 'removed_vendor_grants':dropped,'target_intersections':changes,'removed_platform_health_grants':health,
 'all_original_attribute_definitions_and_assertions_retained':True,'bpf_or_network_readiness_changed':False,
 'inputs_sha256':{str(f):sha(f) for f in [*inputs,config,image,make,sysctl,netctl,manifest,rc,binary,a.baseline]},
 'runner_sha256':sha(Path(__file__)),'runtime_feature_compatibility_proved':False,'security_approved':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
for path,h in inputs.items():assert sha(path)==h
print('STAGED: absent-kernel BPF permissions narrowed;',len(changes),'target intersections; no readiness changes')
