#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile complete permission-frame builder against pinned A17 PermissionMonitor conversion.

Only the Java method declaration is lowered to C++; its integer/flag body and
actual constants are retained. Snapshot collection/order and device runtime are
not established by a pure builder test.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
h=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');sp=importlib.util.spec_from_file_location('extract',h);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
monitor=A/'packages/modules/Connectivity/service/src/com/android/server/connectivity/PermissionMonitor.java';service=A/'frameworks/base/services/permission/java/com/android/server/permission/access/permission/PermissionService.kt';header=A/'packages/modules/Connectivity/bpf/progs/netd.h';aids=A/'system/core/libcutils/include/private/android_filesystem_config.h';text=monitor.read_text();hs=header.read_text();kt=service.read_text()
assert re.search(r'#define AID_USER_OFFSET\s+100000\b',aids.read_text())
constants=re.findall(r'public static final int (PERMISSION_BPF_MAP_BIT_\w+)\s*=\s*([^;]+);',text);assert len(constants)==10
fn=m.extract(text,'convertToChunkPermissionBits');assert fn.startswith('    private int ') or fn.startswith('private int ');fn=fn.replace('private int ','static int ',1)
assert 'if (permissionBits != 0)' in kt and 'uidsPermissionBits[UserHandle.getUid(userId, Process.ROOT_UID)] =' in kt and 'uidsPermissionBits[UserHandle.getUid(userId, Process.SYSTEM_UID)] =' in kt
assert '((1L shl permissionNames.size) - 1).toInt()' in kt
defines=hs[hs.index('// LINT.IfChange(uid_permission_chunk_type)'):hs.index('// LINT.ThenChange(../../common/src/com/android/net/module/util/bpf/UidPermissionChunk.java)')]
code='''#include "Gta3xlwifiPermissionBootstrap.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
using B=android::net::gta3xlwifi::PermissionBootstrap;
using U=android::net::gta3xlwifi::UidPermissionState;
namespace Oracle {
static bool mIsLoopbackPermissionEnabled;
'''+defines+'\n'+'\n'.join('static constexpr int '+n+'='+v+';' for n,v in constants)+'\n'+fn+'\n}\n'+r'''
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
static std::vector<U::Entry> values(const U&u){std::vector<U::Entry> v;assert(!u.snapshot(&v));return v;}
static B::Snapshot frame(){B::Snapshot f;f.users={0};f.knownUids={10001,10002,10002};f.observed={{0,1023},{1000,1023},{10001,4}};return f;}
static void rejected(const B::Snapshot&f,int error){U output;assert(!output.set(777,1));auto before=values(output);T(B::compile(f,&output)==error&&values(output)==before);}
int main(){
 static_assert(B::PerUserRange==100000&&B::MaxEntries==65536);
 for(bool loop:{false,true})for(unsigned raw=0;raw<1024;raw++){Oracle::mIsLoopbackPermissionEnabled=loop;uint32_t out=777;assert(!B::convert(raw,loop,&out)&&out==(unsigned)Oracle::convertToChunkPermissionBits(raw));++comparisons;}
 uint32_t sentinel=777;T(B::convert(1024,true,&sentinel)==-EINVAL&&sentinel==777);T(B::convert(UINT32_MAX,false,&sentinel)==-EINVAL&&sentinel==777);T(B::convert(4,true,nullptr)==-EINVAL);T(B::compile(frame(),nullptr)==-EINVAL);
 for(bool loop:{false,true}){auto f=frame();f.loopbackPermissionEnabled=loop;U out;T(B::compile(f,&out)==0);uint32_t mask=777;T(!out.get(0,&mask)&&mask==(loop?123u:3u));T(!out.get(1000,&mask)&&mask==(loop?123u:3u));T(!out.get(10001,&mask)&&mask==0);T(!out.get(10002,&mask)&&mask==4);T(values(out).size()==3);f.observed.push_back({10003,0});f.knownUids.push_back(10003);T(!B::compile(f,&out)&&!out.get(10003,&mask)&&mask==4);}
 {auto f=frame();f.users={0,10,21474};f.observed.insert(f.observed.end(),{{1000000,1023},{1001000,1023},{2147400000,1023},{2147401000,1023},{1010001,4},{INT_MAX,4}});f.knownUids.insert(f.knownUids.end(),{1010001,1010002,INT_MAX});U out;uint32_t mask;T(!B::compile(f,&out)&&!out.get(1010001,&mask)&&mask==0);T(!out.get(1010002,&mask)&&mask==4);T(!out.get(INT_MAX,&mask)&&mask==0);}
 for(unsigned which=0;which<13;which++){auto f=frame();int error=-EINVAL;switch(which){case 0:f.users.clear();error=-EPROTO;break;case 1:f.users={1};error=-EPROTO;break;case 2:f.users={0,0};break;case 3:f.users.push_back(-1);break;case 4:f.users.push_back(INT_MAX);break;case 5:f.observed.erase(f.observed.begin());error=-EPROTO;break;case 6:f.observed[1].bits=1022;error=-EPROTO;break;case 7:f.observed.push_back({10001,4});break;case 8:f.observed.push_back({-1,4});break;case 9:f.observed.push_back({10003,1024});break;case 10:f.observed.push_back({110001,4});error=-EPROTO;break;case 11:f.knownUids.push_back(-1);break;case 12:f.knownUids.push_back(110001);error=-EPROTO;break;}rejected(f,error);}
 for(unsigned part=0;part<3;part++){auto f=frame();if(part==0)f.users.resize(65537);else if(part==1)f.knownUids.resize(65537);else f.observed.resize(65537);rejected(f,-E2BIG);}
 {auto f=frame();f.users={0,1};f.observed={{0,1023},{1000,1023},{100000,1023},{101000,1023}};f.knownUids.clear();for(int uid=2000;uid<62000;uid++)f.observed.push_back({uid,1});for(int uid=80000;uid<140000;uid++)f.knownUids.push_back(uid);rejected(f,-E2BIG);}
 {auto f=frame();f.users={0,1};f.observed={{0,1023},{1000,1023},{100000,1023},{101000,1023}};f.knownUids.clear();for(int uid=2000;uid<61000;uid++)f.observed.push_back({uid,4});for(int uid=80000;uid<139000;uid++)f.knownUids.push_back(uid);U out;T(!B::compile(f,&out)&&values(out).size()==59002);}
 printf("passed_cases=%u actual_A17_conversion_comparisons=%u\n",cases,comparisons);return 0;
}
''';(O/'test.cpp').write_text(code);sources=[S/'Gta3xlwifiPermissionBootstrap.cpp',S/'Gta3xlwifiUidPermissionState.cpp'];cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(S),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=120,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);match=re.fullmatch(r'passed_cases=(\d+) actual_A17_conversion_comparisons=2048\n',x.stdout);assert match
paths=[Path(__file__),h,monitor,service,header,aids,O/'test.cpp',*sources,*[p.with_suffix('.h') for p in sources]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'actual_A17_conversion_comparisons':2048,'observed_canonical_zero_preserved':True,'missing_known_uid_explicit_no_internet':True,'complete_core_user_coverage_required':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
