#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual platform metadata parser and kernel predicate with explicit host property/version fixtures.

No BPF syscall, loader, property-area mutation or device operation is performed.
The installed candidate is only genuine upstream version-comment data. Missing or
malformed metadata must still abort; capability tests must not invent support.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['composition','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();C=a.composition;O=a.output;assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
rel='device/samsung/gta3xlwifi/configs/netbpfload-version.rc';rc=C/'files'/rel;platform=C/'platform-netbpfload.rc';assert rc.read_bytes().splitlines()[0]==platform.read_bytes().splitlines()[0]
assert all(not x.strip() or x.lstrip().startswith('#') for x in rc.read_text().splitlines())
assert 'bpf.progs_loaded' not in rc.read_text()
source=(C/'BpfUtils.h').read_text();f=re.search(r'static inline int get_api_level_full\(\) \{.*?\n\}',source,re.S).group()
fixture=r'''
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#define PROP_VALUE_MAX 92
static std::string mode,metadata;
static int android_get_device_api_level(){return mode=="pre36"?35:37;}
static int __system_property_get(const char* key,char* value){
 const char* s=!strcmp(key,"ro.build.type")?"userdebug":mode=="invalid-sdk"?"invalid":"37.0";
 strcpy(value,s);return strlen(s);
}
namespace base { static std::string GetProperty(const char*,const char*){return mode=="dev"?"Development":"REL";} }
static FILE* fixture_fopen(const char* path,const char* flags){
 if(strcmp(path,"/system/etc/init/netbpfload.rc"))abort();
 if(mode=="missing")return nullptr;
 return fopen(metadata.c_str(),flags);
}
#define fopen fixture_fopen
'''
main='''
#undef fopen
int main(int argc,char**argv){if(argc!=3)return 91;mode=argv[1];metadata=argv[2];int result=get_api_level_full();printf("%d\\n",result);return 0;}
'''
cpp=O/'api.cpp';cpp.write_text(fixture+f+main);exe=O/'api';subprocess.run(['g++','-std=c++17','-O1','-Wall','-Wextra','-Werror',str(cpp),'-o',str(exe)],check=True)
metadata_tests=[]
for mode in ['rel','dev','pre36']:
 results=[]
 for path in [platform,rc]:
  r=subprocess.run([str(exe),mode,str(path)],capture_output=True,text=True);assert r.returncode==0;results.append(r.stdout)
 assert results[0]==results[1];metadata_tests.append({'mode':mode,'both_original_and_comments_only_result':results[0].strip()})
for mode in ['missing','invalid-sdk']:
 r=subprocess.run([str(exe),mode,str(rc)],capture_output=True,text=True);assert r.returncode==-6;metadata_tests.append({'mode':mode,'expected_SIGABRT':True})
bad=O/'malformed.rc';bad.write_text('# malformed\n');r=subprocess.run([str(exe),'rel',str(bad)],capture_output=True,text=True);assert r.returncode==-6;metadata_tests.append({'mode':'malformed','expected_SIGABRT':True})
krel='packages/modules/Connectivity/bpf/headers/include/bpf/KernelUtils.h';kernel_tests={}
kfixture='''
#include <cstdio>
#include <cstring>
#define KVER(a,b,c) (((a)<<24)+((b)<<16)+(c))
static unsigned kernelVer,minSupportedKernelVer;
'''
kmain=r'''
int main(int argc,char**argv){
 if(argc==2&&!strcmp(argv[1],"counterexample")){kernelVer=KVER(4,4,302);minSupportedKernelVer=KVER(5,10,0);printf("%d\n",isAtLeastKernelVersion(5,8));return 0;}
 bool supportedOnly=argc==2&&!strcmp(argv[1],"supported");unsigned count=0;
 for(unsigned minimum:{KVER(4u,4u,0u),KVER(4u,19u,0u),KVER(5u,4u,0u),KVER(5u,10u,0u),KVER(6u,1u,0u)})
 for(unsigned major=3;major<=7;major++)for(unsigned minor=0;minor<=20;minor++){
  kernelVer=KVER(major,minor,302u);minSupportedKernelVer=minimum;if(supportedOnly&&kernelVer<minimum)continue;
  for(unsigned qm=3;qm<=7;qm++)for(unsigned qn=0;qn<=20;qn++){
   if(isAtLeastKernelVersion(qm,qn)!=(kernelVer>=KVER(qm,qn,0u))) { return 92; }
   count++;
  }
 }
 printf("%u\n",count);return 0;
}
'''
for kind in ['baseline','files']:
 text=(C/kind/krel).read_text();func=re.search(r'static inline bool isAtLeastKernelVersion\([^)]*\) \{.*?\n\}',text,re.S).group();cpp=O/(kind+'-kernel.cpp');cpp.write_text('#include <initializer_list>\n'+kfixture+func+kmain);exe=O/(kind+'-kernel');subprocess.run(['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror',str(cpp),'-o',str(exe)],check=True)
 r=subprocess.run([str(exe),'supported' if kind=='baseline' else 'all'],capture_output=True,text=True);assert r.returncode==0,r.stderr
 c=subprocess.run([str(exe),'counterexample'],capture_output=True,text=True);assert c.stdout.strip()=='0'
 kernel_tests[kind]={'checks_passed':int(r.stdout),'kernel4_4_claims_ring_buffer5_8':bool(int(c.stdout)),'actual_function_sha256':hashlib.sha256(func.encode()).hexdigest()}
# Compile the entire real header with the production Clang warning in both
# native platform and APEX modes; zero minimum is the actual failed variant.
clang=Path('/srv/android/src/lineage-24.0-arm64/prebuilts/clang/host/linux-x86/clang-r596125/bin/clang++')
stub=O/'include/sys/system_properties.h';stub.parent.mkdir(parents=True);stub.write_text('#pragma once\n#define PROP_VALUE_MAX 92\n#define __unused __attribute__((unused))\nstatic inline int __system_property_get(const char*,char*) { return 0; }\n')
full_header_tests=[]
for kind in ['baseline','files']:
 header=C/kind/krel
 for variant in ['platform','apex']:
  cpp=O/(kind+'-'+variant+'.cpp');cpp.write_text('#include "'+str(header.resolve())+'"\nint main(){ return android::bpf::isAtLeastKernelVersion(0,0)?0:1; }\n')
  cmd=[str(clang),'-std=gnu++20','-O2','-Wall','-Wextra','-Werror','-Wtautological-unsigned-zero-compare','-D__ANDROID_API__=10000','-I'+str(O/'include'),str(cpp),'-o',str(O/(kind+'-'+variant))]
  if variant=='apex':cmd.insert(1,'-D__ANDROID_APEX__')
  result=subprocess.run(cmd,capture_output=True,text=True)
  expected_failure=(kind=='baseline' and variant=='apex')
  if expected_failure:assert result.returncode!=0 and 'tautological-unsigned-zero-compare' in result.stderr
  else:assert result.returncode==0,result.stderr
  full_header_tests.append({'kind':kind,'variant':variant,'command':cmd,'exit':result.returncode,'expected_failure':expected_failure,'stderr':result.stderr})
r={'passed':True,'scope':__doc__,'metadata_tests':metadata_tests,'parser_source_sha256':sha(C/'BpfUtils.h'),'parser_actual_function_sha256':hashlib.sha256(f.encode()).hexdigest(),'metadata_first_line_identical_to_upstream':True,'metadata_comments_only':True,'BPF_readiness_not_set':True,'kernel_tests':kernel_tests,'full_header_tests':full_header_tests,'APEX_zero_minimum_compile_regression_proven':True,'source_sha256':{str(p.relative_to(C/'files')):sha(p) for p in (C/'files').rglob('*') if p.is_file()},'upstream_metadata_source_sha256':sha(platform),'actual_Android_LMKD_execution_proven':False,'flash_ready':False};(O/'report.json').write_text(json.dumps(r,indent=2)+'\n');print('PASS original metadata parser, retained aborts, real capability matrix and supported-kernel equivalence')
