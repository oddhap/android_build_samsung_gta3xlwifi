#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check candidate seven-bit permission VALUES against actual A17 expressions.

Extracted loopback UID predicate and migrated socket-create NoInternet branch;
permission map/credentials are fixtures. No kernel permission storage, socket
creation, packet policy, callback publication or readiness is established.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
header=A/'packages/modules/Connectivity/bpf/progs/netd.h';reference=header.with_name('netd.c');h=header.read_text();r=reference.read_text();aids=A/'system/core/libcutils/include/private/android_filesystem_config.h'
assert re.search(r'#define AID_USER_OFFSET\s+100000\b',aids.read_text()) and re.search(r'#define AID_APP_START\s+10000\b',aids.read_text())
defines=h[h.index('// LINT.IfChange(uid_permission_chunk_type)'):h.index('// LINT.ThenChange(../../common/src/com/android/net/module/util/bpf/UidPermissionChunk.java)')]
create=m.extract(r,'inet_socket_create');branch=re.search(r'return \(get_chunk_permissions\(uid\) & PERMISSION_BIT_NO_INTERNET\)\s*\? BPF_DISALLOW\s*:\s*BPF_ALLOW;',create).group()
code=r'''
#include "Gta3xlwifiUidPermissionState.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
using P=android::net::gta3xlwifi::UidPermissionState;
namespace Oracle{
#define function static
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
static std::map<uint32_t,uint32_t> values;
static uint8_t get_chunk_permissions(uint32_t uid){auto i=values.find(uid);return i==values.end()?0:i->second;}
static constexpr int BPF_ALLOW=1,BPF_DISALLOW=0;
'''+defines+'\n'+m.extract(h,'is_system_uid')+'\n'+m.extract(r,'can_force_loopback')+'\n'+m.extract(r,'uids_have_loopback_permissions')+'\nstatic int migrated_create(uint32_t uid){'+branch+'}\n}\n'+r'''
static_assert(P::KnownMask==UID_PERMISSION_MASK&&PERMISSION_COUNT==7);
static_assert(P::AccessLocalNetwork==PERMISSION_BIT_ACCESS_LOCAL_NETWORK);
static_assert(P::UpdateDeviceStats==PERMISSION_BIT_UPDATE_DEVICE_STATS);
static_assert(P::NoInternet==PERMISSION_BIT_NO_INTERNET);
static_assert(P::UseLoopbackInterface==PERMISSION_BIT_USE_LOOPBACK_INTERFACE);
static_assert(P::ForceUseLoopbackInterface==PERMISSION_BIT_FORCE_USE_LOOPBACK_INTERFACE);
static_assert(P::InteractAcrossUsersFull==PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL);
static_assert(P::InteractAcrossUsersOrProfiles==PERMISSION_BIT_INTERACT_ACROSS_USERS_OR_PROFILES);
unsigned cases=0,loopback=0,noInternet=0;
#define T(x) do{assert(x);++cases;}while(0)
int main(){
 P p;uint32_t mask=777;bool allowed=false;std::vector<P::Entry> entries{{777,1}};std::vector<int32_t> members{777};
 T(p.get(10001,&mask)==0&&mask==0);T(p.noInternetDenied(10001,&allowed)==0&&!allowed);
 T(p.get(-1,&mask)==-EINVAL&&mask==0);T(p.get(0,nullptr)==-EINVAL);
 T(p.set(-1,1)==-EINVAL);T(p.set(10001,128)==-EINVAL);T(p.set(10001,UINT32_MAX)==-EINVAL);T(p.remove(-1)==-EINVAL);
 T(p.set(10001,P::AccessLocalNetwork)==0);T(p.noInternetDenied(10001,&allowed)==0&&!allowed);
 T(p.set(10001,P::NoInternet)==0);T(p.noInternetDenied(10001,&allowed)==0&&allowed);
 T(p.noInternetDenied(-1,&allowed)==-EINVAL&&allowed);T(p.noInternetDenied(0,nullptr)==-EINVAL);
 T(p.loopbackAllowed(1,110001,nullptr)==-EINVAL);
 T(p.snapshot(nullptr)==-EINVAL);T(p.matchingUids(0,&members)==-EINVAL&&members==std::vector<int32_t>{777});T(p.matchingUids(128,&members)==-EINVAL&&members==std::vector<int32_t>{777});T(p.matchingUids(1,nullptr)==-EINVAL);
 T(p.replace({{10003,1},{10001,2},{10002,0}})==0);T(p.snapshot(&entries)==0&&(entries==std::vector<P::Entry>{{10001,2},{10003,1}}));auto before=entries;
 T(p.replace({{10001,1},{10001,2}})==-EINVAL);T(p.snapshot(&entries)==0&&entries==before);
 T(p.replace({{10001,1},{-1,2}})==-EINVAL);T(p.snapshot(&entries)==0&&entries==before);
 T(p.replace({{10001,1},{10002,128}})==-EINVAL);T(p.snapshot(&entries)==0&&entries==before);
 T(p.set(INT_MAX,P::KnownMask)==0);T(p.matchingUids(P::InteractAcrossUsersFull|P::ForceUseLoopbackInterface,&members)==0&&members==std::vector<int32_t>{INT_MAX});
 T(p.remove(10001)==0);T(p.get(10001,&mask)==0&&mask==0);T(p.set(INT_MAX,0)==0);T(p.snapshot(&entries)==0&&(entries==std::vector<P::Entry>{{10003,1}}));
 const uint32_t uids[]={0,1000,10001,110001,110002,100001,65534,INT_MAX};
 for(uint32_t sender:uids)for(uint32_t receiver:uids){
  P value;
  for(uint32_t sm=0;sm<=P::KnownMask;sm++)for(uint32_t rm=0;rm<=P::KnownMask;rm++){
   assert(value.set(sender,sm)==0&&value.set(receiver,rm)==0);Oracle::values.clear();Oracle::values[sender]=sm;Oracle::values[receiver]=rm;
   assert(value.loopbackAllowed(sender,receiver,&allowed)==0&&allowed==Oracle::uids_have_loopback_permissions(sender,receiver));++loopback;
   bool denied=true;assert(value.noInternetDenied(sender,&denied)==0&&denied==(Oracle::migrated_create(sender)==Oracle::BPF_DISALLOW));++noInternet;
  }
 }
 P edge;Oracle::values.clear();
 for(uint32_t sender:{0u,10001u,UINT32_MAX})for(uint32_t receiver:{0u,10001u,UINT32_MAX}){T(edge.loopbackAllowed(sender,receiver,&allowed)==0&&allowed==Oracle::uids_have_loopback_permissions(sender,receiver));}
 T(edge.set(10001,P::InteractAcrossUsersFull)==0);T(edge.loopbackAllowed(10001,UINT32_MAX,&allowed)==0&&allowed);
 // This is the pure UID predicate: real sender65534 is NOT normalized here.
 // Packet bpf_traffic_account performs that separate normalization to0 first.
 T(edge.loopbackAllowed(65534,110001,&allowed)==0&&!allowed);T(edge.loopbackAllowed(0,110001,&allowed)==0&&allowed);
 printf("passed_cases=%u loopback=%u no_internet=%u\n",cases,loopback,noInternet);
}
'''
(O/'test.cpp').write_text(code);source=S/'Gta3xlwifiUidPermissionState.cpp';decl=S/'Gta3xlwifiUidPermissionState.h';cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(S),str(source),str(O/'test.cpp'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=120);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.fullmatch(r'passed_cases=(\d+) loopback=(\d+) no_internet=(\d+)\n',x.stdout);assert match and int(match[1])>=40 and int(match[2])==int(match[3])==1048576
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,header,reference,aids,source,decl,O/'test.cpp']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_android17_loopback_permission_comparisons':int(match[2]),'actual_android17_migrated_create_value_comparisons':int(match[3]),'stderr':x.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual A17 loopback/migrated-create expressions, value-only fatal UBSan')
