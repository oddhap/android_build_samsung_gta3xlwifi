#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the actual vold predicate; reproduce null dereference and preserve metadata flag semantics.

The host fixture supplies only in-memory Fstab entries; no partition, key, policy
or device is accessed. This is a regression proof, not Android FBE execution.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['composition','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();C=a.composition;O=a.output;assert not O.exists();O.mkdir(parents=True)
rel='system/vold/FsCrypt.cpp';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
fixture=r'''
#include <string>
#include <vector>
struct Flags { bool wrapped_key; };
struct Entry { std::string mount_point; Flags fs_mgr_flags; };
static std::vector<Entry> fstab_default;
static const char* METADATA_MNT_POINT = "/metadata";
static Entry* GetEntryForMountPoint(std::vector<Entry>* f, const char* p) {
  for (auto& e:*f) if (e.mount_point == p) return &e;
  return nullptr;
}
'''
main=r'''
int main(int argc,char**argv) {
  if(argc!=2)return 90;
  std::string mode=argv[1];bool expected=false;
  if(mode=="empty") {}
  else if(mode=="data-raw") fstab_default={{"/data",{false}}};
  else if(mode=="data-wrapped") fstab_default={{"/data",{true}}};
  else if(mode=="metadata-raw") fstab_default={{"/metadata",{false}}};
  else if(mode=="metadata-wrapped") {fstab_default={{"/metadata",{true}}};expected=true;}
  else if(mode=="mixed-wrapped") {fstab_default={{"/data",{false}},{"/metadata",{true}}};expected=true;}
  else if(mode=="mixed-raw") fstab_default={{"/data",{true}},{"/metadata",{false}}};
  else return 91;
  return is_metadata_wrapped_key_supported()==expected?0:92;
}
'''
results={}
for kind in ['baseline','files']:
 src=C/kind/rel;text=src.read_text();m=re.search(r'bool is_metadata_wrapped_key_supported\(\) \{[^}]*\}',text);assert m
 cpp=O/(kind+'.cpp');cpp.write_text(fixture+m.group()+main);exe=O/kind
 cmd=['g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(cpp),'-o',str(exe)]
 subprocess.run(cmd,check=True,capture_output=True)
 modes=['empty'] if kind=='baseline' else ['empty','data-raw','data-wrapped','metadata-raw','metadata-wrapped','mixed-wrapped','mixed-raw']
 tests=[]
 for mode in modes:
  r=subprocess.run([str(exe),mode],capture_output=True,text=True);tests.append({'mode':mode,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  if kind=='baseline':assert r.returncode!=0 and 'null pointer' in r.stderr
  else:assert r.returncode==0,(mode,r.stderr)
 results[kind]={'source_sha256':sha(src),'actual_function_sha256':hashlib.sha256(m.group().encode()).hexdigest(),'compile_command':cmd,'tests':tests}
r={'passed':True,'scope':__doc__,'baseline_null_dereference_reproduced':True,'fixed_cases_passed':7,'source_sha256':{rel:sha(C/'files'/rel)},'results':results,'actual_Android_FBE_proven':False,'flash_ready':False};(O/'report.json').write_text(json.dumps(r,indent=2)+'\n');print('PASS actual predicate: baseline null dereference reproduced; 7 fixed cases')
