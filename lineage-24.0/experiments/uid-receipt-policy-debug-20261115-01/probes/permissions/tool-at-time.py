#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Query actual strict compiled policy permissions using Android17 libsepol.

No policy, context, kernel, source or device input is replaced. A permission
query alone does not validate pathname labeling, DAC, kernel restrictions or I/O.
"""
import argparse,hashlib,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--top',type=Path,required=True);p.add_argument('--policy',type=Path,required=True);p.add_argument('--queries',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();strict=a.policy.parent/'report.json';meta=json.loads(strict.read_text());assert meta['passed_strict']
entries=[x for x in meta['results'] if x['neverallow_checks_enabled'] and x['exit_code']==0];assert len(entries)==1 and entries[0]['compiled_policy_sha256']==sha(a.policy)
source=O/'query.c';source.write_text(r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb/services.h>
int main(int argc,char **argv){
 assert(argc>2&&(argc-2)%4==0);FILE *f=fopen(argv[1],"rb");assert(f);assert(fseek(f,0,SEEK_END)==0);long n=ftell(f);assert(n>0);rewind(f);void *data=malloc(n);assert(data);assert(fread(data,1,n,f)==(size_t)n);assert(fclose(f)==0);assert(sepol_load_policy(data,n)==0);free(data);
 for(int i=2;i<argc;i+=4){
  sepol_security_id_t s,t;sepol_security_class_t c;sepol_access_vector_t permission;struct sepol_av_decision av;
  assert(sepol_context_to_sid(argv[i],strlen(argv[i])+1,&s)==0);
  assert(sepol_context_to_sid(argv[i+1],strlen(argv[i+1])+1,&t)==0);
  assert(sepol_string_to_security_class(argv[i+2],&c)==0);
  assert(sepol_string_to_av_perm(c,argv[i+3],&permission)==0);
  assert(sepol_compute_av(s,t,c,permission,&av)==0);
  printf("%d %u\n",(i-2)/4,(av.allowed&permission)==permission);
 }
 return 0;
}
''')
cc=T/'prebuilts/clang/host/linux-x86/clang-r584948/bin/clang';lib=T/'out/soong/.intermediates/external/selinux/libsepol/libsepol/linux_glibc_x86_64_static/libsepol.a';exe=O/'query'
analyzer=T/'out/host/linux-x86/bin/sepolicy-analyze'
inputs={str(p.resolve()):sha(p) for p in [a.policy,strict,a.queries,Path(__file__),source,cc,lib,analyzer]}
(O/'tool-at-time.py').write_bytes(Path(__file__).read_bytes())
check=subprocess.run([str(analyzer),str(a.policy),'permissive'],capture_output=True,text=True);assert check.returncode==0 and not check.stdout and not check.stderr,(check.stdout,check.stderr)
cmd=[str(cc),'-fuse-ld=lld','-std=gnu11','-Wall','-Wextra','-Werror','-I'+str(T/'external/selinux/libsepol/include'),str(source),str(lib),'-o',str(exe)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
queries=json.loads(a.queries.read_text());assert queries and all(set(q)=={'source','target','class','permission','expected'} for q in queries)
args=[str(exe),str(a.policy.resolve())]
for q in queries:
 assert q['expected'] in ['allow','deny','observe'];args.extend(q[k] for k in ['source','target','class','permission'])
r=subprocess.run(args,capture_output=True,text=True);(O/'query.log').write_text(r.stdout+r.stderr);assert r.returncode==0,(r.stdout,r.stderr)
rows=[line for line in r.stdout.splitlines() if not line.startswith('libsepol.policydb_index_others: security: ')];assert len(rows)==len(queries),(r.stdout,r.stderr);results=[]
for i,(q,line) in enumerate(zip(queries,rows)):
 index,allowed=map(int,line.split());assert index==i and allowed in [0,1],(q,line)
 result={**q,'allowed':bool(allowed),'no_permissive_domains':True};results.append(result)
expected_ok=all(q['expected']=='observe' or q['allowed']==(q['expected']=='allow') for q in results)
for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
(O/'report.json').write_text(json.dumps({'passed':expected_ok,'scope':__doc__,'policy_sha256':sha(a.policy),'strict_assertions_bound':True,'inputs_sha256':inputs,'queries':results,'compile_command':cmd,'no_permissive_domains':True,'hardware_tested':False},indent=2)+'\n')
assert expected_ok,[q for q in results if q['expected']!='observe' and q['allowed']!=(q['expected']=='allow')]
print('PASS: '+str(len(results))+' real compiled-policy permission queries; no permissive domains, strict assertion report bound')
