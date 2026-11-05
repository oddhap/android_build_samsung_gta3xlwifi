#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate installed platform and staged Samsung contexts against a strict policy.

No filesystem/image relabeling or runtime validation is performed.
"""
import argparse,hashlib,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','vendor','policy','output']:p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--out-dir',default='out')
a=p.parse_args();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert not a.output.exists() and not a.output.resolve().is_relative_to(a.top.resolve())
a.output.mkdir();tools=a.top/'out/host/linux-x86/bin';assert a.out_dir in ['out','out-policy-user-20261101-01']
prod=a.top/a.out_dir/'target/product/gta3xlwifi'
roots=[prod/'system/etc/selinux',prod/'system/system_ext/etc/selinux',prod/'product/etc/selinux',a.vendor/'etc/selinux']
inputs={str(a.policy):sha(a.policy)};results=[];seapps=[];keys=[];props=[];tees=[]
for root in roots:
 for path in sorted(root.glob('*_contexts')):
  inputs[str(path)]=sha(path)
  if path.name.endswith('_keystore2_key_contexts'):keys.append(path);continue
  if path.name.endswith('_tee_service_contexts'):tees.append(path);continue
  kind=path.name.rsplit('_',2)[-2]
  if kind=='seapp':seapps.append(path);continue
  if kind=='property':props.append(path)
  flag={'file':[],'property':['-p'],'service':['-s'],'hwservice':['-l'],'vndservice':['-v']}.get(kind)
  assert flag is not None,path
  cmd=[str(tools/'checkfc'),*flag,'-e',str(a.policy),str(path)]
  r=subprocess.run(cmd,capture_output=True,text=True);name=str(len(results))+'.log';(a.output/name).write_text(r.stdout+r.stderr)
  results.append({'command':cmd,'exit_code':r.returncode,'log':name})
cmd=[str(tools/'property_info_checker'),str(a.policy),*[str(x) for x in props]]
r=subprocess.run(cmd,capture_output=True,text=True);(a.output/'property-info.log').write_text(r.stdout+r.stderr)
results.append({'command':cmd,'exit_code':r.returncode,'log':'property-info.log'})
# Validate key-context namespace syntax, uniqueness and actual policy labels with libsepol.
keyrows=[];seen=set()
for path in keys:
 for line in path.read_text().splitlines():
  line=line.split('#',1)[0].strip()
  if not line:continue
  namespace,context=line.split();assert namespace.isdecimal() and 0<=int(namespace)<2**31
  assert int(namespace) not in seen;seen.add(int(namespace));keyrows.extend(['keystore2_key_type',context])
for path in tees:
 seen_tee=set()
 for line in path.read_text().splitlines():
  line=line.split('#',1)[0].strip()
  if not line:continue
  name,context=line.split();assert name not in seen_tee;seen_tee.add(name)
  keyrows.extend(['tee_service_type',context])
csource=a.output/'check-key-context.c'
csource.write_text('''#include <assert.h>
#include <stdio.h>
#include <sepol/context.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
int main(int argc,char **argv){
 assert(argc>=2 && argc%2==0);FILE *f=fopen(argv[1],"rb");assert(f);
 sepol_policydb_t *p;sepol_policy_file_t *pf;sepol_handle_t *h=sepol_handle_create();
 assert(h&&sepol_policydb_create(&p)==0&&sepol_policy_file_create(&pf)==0);
 sepol_policy_file_set_fp(pf,f);assert(sepol_policydb_read(p,pf)==0);
 for(int i=2;i<argc;i+=2){sepol_context_t *c;assert(sepol_context_from_string(h,argv[i+1],&c)==0);assert(sepol_context_check(h,p,c)==0);
 type_datum_t *a=hashtab_search(p->p.p_types.table,argv[i]);assert(a && a->flavor==TYPE_ATTRIB);
 type_datum_t *t=hashtab_search(p->p.p_types.table,(char*)sepol_context_get_type(c));assert(t && t->flavor==TYPE_TYPE);
 assert(ebitmap_get_bit(&p->p.type_attr_map[t->s.value-1],a->s.value-1));sepol_context_free(c);}
 sepol_policy_file_free(pf);sepol_policydb_free(p);sepol_handle_destroy(h);fclose(f);return 0;
}
''')
lib=a.top/'out/soong/.intermediates/external/selinux/libsepol/libsepol/linux_glibc_x86_64_static/libsepol.a'
cc=a.top/'prebuilts/clang/host/linux-x86/clang-r584948/bin/clang'
cmd=[str(cc),'-fuse-ld=lld','-std=gnu11','-Wall','-Wextra','-Werror','-I'+str(a.top/'external/selinux/libsepol/include'),str(csource),str(lib),'-o',str(a.output/'check-key-context')]
r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
inputs[str(lib)]=sha(lib);inputs[str(cc)]=sha(cc)
cmd=[str(a.output/'check-key-context'),str(a.policy),*keyrows]
r=subprocess.run(cmd,capture_output=True,text=True);(a.output/'key-contexts.log').write_text(r.stdout+r.stderr)
results.append({'command':cmd,'exit_code':r.returncode,'log':'key-contexts.log','key_and_tee_label_count':len(keyrows)//2})
neverallows=a.top/a.out_dir/'soong/.intermediates/system/sepolicy/contexts/vendor_seapp_contexts/android_common/gta3xlwifi/neverallow'
assert neverallows.is_file();inputs[str(neverallows)]=sha(neverallows)
assert any(line.startswith('neverallow ') for line in neverallows.read_text().splitlines())
combined=a.output/'combined_seapp_contexts';combined.write_text('\n'.join(x.read_text() for x in seapps)+'\n'+neverallows.read_text()+'\n')
cmd=[str(tools/'checkseapp'),'-p',str(a.policy),str(combined)]
r=subprocess.run(cmd,capture_output=True,text=True);(a.output/'seapp.log').write_text(r.stdout+r.stderr)
results.append({'command':cmd,'exit_code':r.returncode,'log':'seapp.log'})
for path,expected in inputs.items():assert sha(Path(path))==expected
report={'passed':all(x['exit_code']==0 for x in results),'inputs_sha256':inputs,'results':results,'tool_sha256':{str(tools/n):sha(tools/n) for n in ['checkfc','checkseapp','property_info_checker']},'runtime_validated':False,'flash_ready':False}
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
for x in results:
 if x['exit_code']:print('FAIL',x['command'][-1],(a.output/x['log']).read_text()[:2000])
print('Context checks:',len(results),'passed:',report['passed']);raise SystemExit(0 if report['passed'] else 1)
