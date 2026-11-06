#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare actual Android17 root-chain command generation before/after guard insertion.

Extracts the real createChildChains bodies. Existing-chain lookup, properties
and command execution are fixtures; no kernel/rule/service is accessed.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
spec=importlib.util.spec_from_file_location('extract',Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
old=m.extract(R.read_text(),'Controllers::createChildChains');new=m.extract(S.read_text(),'Controllers::createChildChains')
prefix=r'''
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>
enum IptablesTarget{V4,V6,V4V6};
struct State{bool legacy=false;std::set<std::string> existing;std::string command;IptablesTarget target=V4;int result=0;unsigned calls=0;} g;
namespace android::base{bool GetBoolProperty(const std::string& name,bool fallback){assert(name=="ro.gta3xlwifi.legacy_networking"&&!fallback);return g.legacy;}}
std::string format(const char* fmt,va_list args){va_list copy;va_copy(copy,args);int n=vsnprintf(nullptr,0,fmt,copy);va_end(copy);assert(n>=0);std::vector<char> b(n+1);assert(vsnprintf(b.data(),b.size(),fmt,args)==n);return std::string(b.data(),n);}
std::string StringPrintf(const char* fmt,...){va_list a;va_start(a,fmt);auto s=format(fmt,a);va_end(a);return s;}
void StringAppendF(std::string* out,const char* fmt,...){va_list a;va_start(a,fmt);*out+=format(fmt,a);va_end(a);}
'''
stub=r'''
static const char* CHILD_CHAIN_TEMPLATE="-A %s -j %s\n";
class Controllers{public:
 static int createChildChains(IptablesTarget,const char*,const char*,const std::vector<const char*>&,bool);
 static std::set<std::string> findExistingChildChains(IptablesTarget,const char*,const char*){return g.existing;}
 static int execIptablesRestore(IptablesTarget target,const std::string& command){++g.calls;g.target=target;g.command=command;return g.result;}
};
'''
code=prefix+'namespace Before{'+stub+old+'}\nnamespace After{'+stub+new+'}\n'+r'''
int main(){unsigned cases=0;
 for(bool legacy:{false,true})for(auto table:{"filter","mangle","raw","nat"})for(auto parent:{"INPUT","FORWARD","OUTPUT","POSTROUTING"})for(bool exclusive:{false,true})for(auto target:{V4,V6,V4V6})for(bool existing:{false,true})for(int result:{0,-1,11}){
  if(target==V4V6&&!exclusive)continue; // Actual lookup rejects this unsupported combination.
  g=State{};g.legacy=legacy;g.result=result;if(existing)g.existing={"child_a"};
  std::vector<const char*> children={"child_a","child_b"};
  assert(Before::Controllers::createChildChains(target,table,parent,children,exclusive)==result);auto before=g.command;assert(g.calls==1&&g.target==target);
  g.calls=0;assert(After::Controllers::createChildChains(target,table,parent,children,exclusive)==result);assert(g.calls==1&&g.target==target);
  std::string expected=before;
  if(legacy&&exclusive&&!strcmp(table,"filter")&&(strcmp(parent,"INPUT")==0||strcmp(parent,"FORWARD")==0||strcmp(parent,"OUTPUT")==0)){
   std::string flush="-F "+std::string(parent)+"\n";auto pos=expected.find(flush);assert(pos!=std::string::npos);
   expected.insert(pos+flush.size(),"-A "+std::string(parent)+" -m gta3xlwifi_guard -j DROP\n");
  }
  assert(g.command==expected);++cases;
 }
 printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(O/'test.cpp'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env);(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
match=re.fullmatch(r'passed_cases=(\d+)\n',r.stdout);assert match and int(match[1])>100
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py'),S,R,O/'test.cpp']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'stderr':r.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip()+'; actual command-builder differential with fatal UBSan')
