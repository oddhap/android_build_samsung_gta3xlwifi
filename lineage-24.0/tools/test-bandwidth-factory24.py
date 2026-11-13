#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute actual A17 and explicit private-backend accounting factories.

Checks exact preserved order/content outside four deliberately omitted metered
parent rows and two genuine producer substitutions. This is pure source factory
validation, not installation, startup sequencing or network readiness.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def extract(s,n):
 start=s.index('std::vector<std::string> '+n+'(');return s[start:s.index('\n}',start)+2]
base=A/'system/netd/server/BandwidthController.cpp';header=A/'system/netd/server/BandwidthController.h';source=S/'BandwidthController.cpp';candidate_header=S/'BandwidthController.h';old=base.read_text();new=source.read_text();stock=extract(old,'getBasicAccountingCommands');assert extract(new,'getBasicAccountingCommands')==stock
legacy=extract(new,'getGta3xlwifiBasicAccountingCommands');getter=extract(new,'BandwidthController::makeGta3xlwifiAccountingCommands');recovered=new.replace(stock+'\n\n'+legacy,stock,1);start=recovered.index('// Pure command construction only.');end=recovered.index('BandwidthController::BandwidthController()',start);assert getter in recovered[start:end];recovered=recovered[:start]+recovered[end:];assert recovered==old,'Change outside explicit factory/getter'
addition='''    // Explicit private-backend factory; no I/O, state changes or readiness.
    // Owner startup must pair these producers with real kernel egress UNDO.
    static std::vector<std::string> makeGta3xlwifiAccountingCommands();

''';assert candidate_header.read_text().replace(addition,'',1)==header.read_text()
fw=A/'system/netd/include/Fwmark.h';permission=fw.with_name('Permission.h');net=A/'system/netd/server/NetdConstants.h';bpf=A/'system/netd/include/mainline/XtBpfProgLocations.h';aidl=A/'packages/modules/Connectivity/staticlibs/netd/aidl_api/netd_aidl_interface/18/android/net/INetd.aidl';m=re.search(r'const int CLAT_MARK = (0x[0-9a-f]+);',aidl.read_text());assert m;clat=m[1]
ipsec=re.search(r'^#define IPSEC_IFACE_PREFIX "([a-z]+)"$',net.read_text(),re.M);assert ipsec and ipsec[1]=='ipsec';commit='const std::string COMMIT_AND_CLOSE = "COMMIT\\n";';assert commit in old
code=r'''
#include <cassert>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include "Fwmark.h"
#include "mainline/XtBpfProgLocations.h"
static std::string StringPrintf(const char*format,...){va_list v;va_start(v,format);va_list copy;va_copy(copy,v);int n=vsnprintf(nullptr,0,format,copy);va_end(copy);assert(n>=0);std::vector<char> text(n+1);assert(vsnprintf(text.data(),text.size(),format,v)==n);va_end(v);return std::string(text.data(),n);}
static uint32_t uidBillingMask=Fwmark::getUidBillingMask();
'''+ '#define IPSEC_IFACE_PREFIX "'+ipsec[1]+'"\nstatic uint32_t CLAT_MARK='+clat+'u;\n'+commit+'\n'+stock+'\n'+legacy+'\nstruct BandwidthController{static std::vector<std::string> makeGta3xlwifiAccountingCommands();};\n'+getter+r'''
static unsigned cases,variants;
#define T(x) do{assert(x);++cases;}while(0)
int main(){
 const std::vector<std::string> removed={
  "-I bw_penalty_box -m bpf --object-pinned " XT_BPF_DENYLIST_PROG_PATH " -j REJECT",
  "-A bw_penalty_box -j bw_happy_box","-A bw_happy_box -j bw_data_saver",
  "-I bw_happy_box -m bpf --object-pinned " XT_BPF_ALLOWLIST_PROG_PATH " -j RETURN"};
 const std::map<std::string,std::string> replacements={
  {"-A bw_raw_PREROUTING -m bpf --object-pinned " XT_BPF_INGRESS_PROG_PATH,"-A bw_raw_PREROUTING -m gta3xlwifi_iface_stats --direction ingress"},
  {"-A bw_mangle_POSTROUTING -m bpf --object-pinned " XT_BPF_EGRESS_PROG_PATH,"-A bw_mangle_POSTROUTING -m gta3xlwifi_iface_stats --direction egress"}};
 for(uint32_t mask:{Fwmark::getUidBillingMask(),0u,1u,0x80000000u,0xffffffffu})for(uint32_t mark:{''' + clat +r'''u,0u,1u,0xffffffffu}){
  uidBillingMask=mask;CLAT_MARK=mark;auto before=getBasicAccountingCommands();auto actual=BandwidthController::makeGta3xlwifiAccountingCommands();auto expected=before;
  for(const auto&line:removed){T(std::count(expected.begin(),expected.end(),line)==1);expected.erase(std::find(expected.begin(),expected.end(),line));}
  for(const auto&[from,to]:replacements){T(std::count(expected.begin(),expected.end(),from)==1);*std::find(expected.begin(),expected.end(),from)=to;}
  T(actual==expected);T(actual.size()+4==before.size());for(const auto&line:actual)T(line.find("-m bpf")==std::string::npos&&line.find("object-pinned")==std::string::npos);
  // Parents are deliberately empty for MeteredRoots, not silently default-allow
  // after publication. This factory itself never installs/releases/publishes.
  for(const auto&line:actual)T(line.rfind("-A bw_penalty_box ",0)!=0&&line.rfind("-I bw_penalty_box ",0)!=0&&line.rfind("-A bw_happy_box ",0)!=0&&line.rfind("-I bw_happy_box ",0)!=0);
  T(actual.back()=="COMMIT\n");T(std::count(actual.begin(),actual.end(),"*filter")==1&&std::count(actual.begin(),actual.end(),"*raw")==1&&std::count(actual.begin(),actual.end(),"*mangle")==1);++variants;
 }
 printf("passed_cases=%u variants=%u\n",cases,variants);
}
'''
(O/'test.cpp').write_text(code);cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(A/'system/netd/include'),str(O/'test.cpp'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=30,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+) variants=(\d+)\n',x.stdout);assert m and int(m[2])==20
paths=[Path(__file__),base,header,source,candidate_header,fw,permission,net,bpf,aidl,O/'test.cpp'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'mark_variants':int(m[2]),'stock_factory_and_other_controller_source_unchanged':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'rules_installed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
