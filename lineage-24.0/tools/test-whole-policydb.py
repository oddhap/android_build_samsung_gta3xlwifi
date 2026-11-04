#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile actual Samsung policydb/AVTAB/bitmap/conditional/MLS readers on Linux.

Kernel allocations, flex arrays, bit operations, logging and panic are host
fixtures. No security_load_policy publication, AVC enforcement, kernel execution
or device boot is tested. A single-bit cap9-off fixture is NEVER installable.
"""
import argparse,hashlib,importlib.util,json,os,re,struct,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for name in ['kernel','kernel-out','policy','inspection','output']:p.add_argument('--'+name,required=True,type=Path)
p.add_argument('--cc',default='clang');a=p.parse_args()
root=Path(__file__).resolve().parent;fixture=root/'fixtures/policydb-host24'
a.kernel=a.kernel.resolve();a.kernel_out=a.kernel_out.resolve();a.policy=a.policy.resolve();a.output=a.output.resolve()
for protected in [a.kernel,a.kernel_out,a.policy.parent]:assert not a.output.is_relative_to(protected)
assert not a.output.exists();a.output.mkdir()
(a.output/'NOT_INSTALLABLE.txt').write_text('Host parser fixtures only. The cap9-off artifact is never an installation policy. Strict policy still fails.\n')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
config=(a.kernel_out/'.config').read_text();assert 'CONFIG_64BIT=y' in config
cmdfile=a.kernel_out/'security/selinux/ss/.policydb.o.cmd';cmd=cmdfile.read_text();assert '-fno-strict-overflow' in cmd
assert not re.search(r'-D\s*CONFIG_ALWAYS_ENFORCE(?:\s|=|$)',cmd)
ss=a.kernel/'security/selinux/ss';inc=a.kernel/'security/selinux/include'
spec=importlib.util.spec_from_file_location('extract',root/'test-netlink-xperm24.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
mls=(ss/'mls.c').read_text();helpers='\n\n'.join(m.function(mls,n) for n in ['mls_level_isvalid','mls_range_isvalid','mls_context_isvalid'])
main=a.output/'main.c';main.write_text('#include <host.h>\n#include "security.h"\n#include "policydb.h"\n#include "mls.h"\nstruct policydb policydb;\n'+helpers+'\n'+(fixture/'driver.c').read_text())
source=[ss/(n+'.c') for n in ['policydb','avtab','ebitmap','hashtab','symtab','conditional']]
command=[a.cc,'-fuse-ld=lld','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-sign-compare','-Wno-unused-function','-fno-strict-overflow','-fno-strict-aliasing','-ffunction-sections','-fdata-sections','-fsanitize=address,undefined','-include',str(fixture/'compat/host.h'),'-I'+str(fixture/'compat'),'-I'+str(inc),'-I'+str(ss),'-I'+str(a.kernel_out/'security/selinux'),str(main),*[str(f) for f in source],'-Wl,--gc-sections','-o',str(a.output/'parser')]
result=subprocess.run(command,capture_output=True,text=True);(a.output/'compile.log').write_text(result.stdout+result.stderr);assert result.returncode==0,result.stderr
raw=a.policy.read_bytes();magic,n=struct.unpack_from('<II',raw);assert magic==0xf97cff8c and raw[8:8+n]==b'SE Linux'
off=8+n;version,_,_,_=struct.unpack_from('<4I',raw,off);assert version==30;off+=16
mapsize,high,count=struct.unpack_from('<3I',raw,off);assert mapsize==64 and count==1;off+=12
start,bits=struct.unpack_from('<IQ',raw,off);assert start==0 and bits&(1<<9);offset=off+4
oracle=json.loads(a.inspection.read_text());assert bits==sum(1<<c['bit'] for c in oracle['enabled_policy_capabilities'])
control=bytearray(raw);struct.pack_into('<Q',control,offset,bits&~(1<<9));assert len(control)==len(raw) and sum(x!=y for x,y in zip(raw,control))==1
controlfile=a.output/'NOT_INSTALLABLE_cap9_off_fixture.bin';controlfile.write_bytes(control)
env=dict(os.environ,UBSAN_OPTIONS='halt_on_error=1');cases=[]
for name,path,panic in [('unmodified-active-cap9',a.policy,True),('single-bit-off-structure-control',controlfile,False)]:
 r=subprocess.run([str(a.output/'parser'),str(path)],capture_output=True,text=True,env=env)
 (a.output/(name+'.log')).write_text(r.stdout+r.stderr)
 if panic:assert r.returncode==77 and 'active netlink_xperm is unsupported' in r.stderr and 'PANIC: SELinux:Failed to load policy' in r.stderr
 else:
  assert r.returncode==0
  expected=f"rc=0 consumed={len(raw)} remaining=0 types={oracle['type_count']} classes={oracle['class_count']}"
  assert expected in r.stdout
  assert f"ioctl={oracle['xperm_kind_counts']['1']} nlmsg={oracle['xperm_kind_counts']['3']}" in r.stdout
 cases.append({'name':name,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
for length in [7,offset-1,offset+8,len(raw)//2,len(raw)-1]:
 f=a.output/f'NOT_INSTALLABLE_truncated_{length}.bin';f.write_bytes(control[:length]);r=subprocess.run([str(a.output/'parser'),str(f)],capture_output=True,text=True,env=env)
 (a.output/f'truncated-{length}.log').write_text(r.stdout+r.stderr);assert r.returncode==77 and 'PANIC:' in r.stderr
 cases.append({'name':f'truncated-{length}','exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
inputs=[*source,*sorted(ss.glob('*.h')),ss/'mls.c',inc/'security.h',inc/'conditional.h',a.kernel_out/'security/selinux/flask.h',a.kernel_out/'.config',cmdfile,a.policy,a.inspection,root/'test-netlink-xperm24.py',Path(__file__),*sorted(x for x in fixture.rglob('*') if x.is_file())]
report={'passed_expected_behavior_tests':True,'scope':__doc__,'original_active_cap9_policy_accepted':False,'original_active_cap9_reaches_panic':True,'cap9_off_fixture_complete_structure_parsed':True,'fixture_modification':'Exactly one byte differs, only capability bit9 cleared; not installation data. Production source/guard unmodified.','actual_policy_binary_sha256':sha(a.policy),'control_sha256':sha(controlfile),'control_byte_offset':offset+1,'cases':cases,'compile_command':command,'host_compiler':subprocess.check_output([a.cc,'--version'],text=True),'production_overflow_flags_preserved':True,'CONFIG_ALWAYS_ENFORCE_macro_defined':False,'inputs_sha256':{str(f):sha(f) for f in inputs},'whole_kernel_policy_load_proven':False,'strict_policy_passed':False,'flash_ready':False}
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: expected active-cap9 panic, complete single-bit-off structure control and five truncated-policy panic controls; NOT kernel load approval')
