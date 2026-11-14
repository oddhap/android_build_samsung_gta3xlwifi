#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind actual generated/compiled UID-migration flag and A17 tagging budget guard.

Read/compile evidence only. Does not authorize a tag, select flags, initialize a
provider, load a BPF object or claim actual installed-framework behavior.
"""
import argparse,fcntl,hashlib,json,os,re,subprocess,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=T/'out/soong/.intermediates/packages/modules/Connectivity/common/com.android.tethering.flags-aconfig-java/android_common_apex31';src=base/'gen/com.android.tethering.flags-aconfig-java.srcjar';jar=base/'javac/com.android.tethering.flags-aconfig-java.jar';javap=T/'prebuilts/jdk/jdk21/linux-x86/bin/javap'
with zipfile.ZipFile(src) as z:text=z.read('com/android/tethering/flags/Flags.java').decode()
method=re.search(r'public static boolean permissionMapUidMigration\(\)\s*\{\s*return true;\s*\}',text);assert method
output=subprocess.check_output([str(javap),'-c','-classpath',str(jar),'com.android.tethering.flags.Flags'],text=True);(O/'flags-javap.txt').write_text(output)
assert re.search(r'public static boolean permissionMapUidMigration\(\);\s+Code:\s+0: iconst_1\s+1: ireturn',output)
(O/'uid-migration-generated-accessor.txt').write_text(method[0]+'\n')
source=T/'packages/modules/Connectivity/bpf/netd/BpfHandler.cpp';header=T/'packages/modules/Connectivity/bpf/progs/netd.h';s=source.read_text();h=header.read_text();size=re.search(r'^#define STATS_MAP_SIZE\s+5000\b.*$',h,re.M);assert size
per=re.search(r'^constexpr int PER_UID_STATS_ENTRIES_LIMIT = 500;$',s,re.M);total=re.search(r'^constexpr int TOTAL_UID_STATS_ENTRIES_LIMIT = STATS_MAP_SIZE \* 0\.9;$',s,re.M);assert per and total
start=s.index('    if (totalEntryCount > mTotalUidStatsEntriesLimit ||');end=s.index('    // Update the tag information',start);guard=s[start:end]
code='#include <cassert>\n#include <cerrno>\n#include <cstdint>\n#include <cstdio>\n#define ALOGE(...) ((void)0)\n'+size[0]+'\n'+per[0]+'\n'+total[0]+r'''
static int check(uint32_t totalEntryCount,uint32_t perUidEntryCount){
 constexpr uint32_t mTotalUidStatsEntriesLimit=TOTAL_UID_STATS_ENTRIES_LIMIT;
 constexpr uint32_t mPerUidStatsEntriesLimit=PER_UID_STATS_ENTRIES_LIMIT;
'''+guard+r'''
 return 0;
}
int main(){assert(PER_UID_STATS_ENTRIES_LIMIT==500&&TOTAL_UID_STATS_ENTRIES_LIMIT==4500);uint32_t values[]={0,499,500,501,4499,4500,4501,5000,UINT32_MAX};unsigned cases=0;for(auto all:values)for(auto uid:values){assert(check(all,uid)==((all>4500||uid>500)?-EMFILE:0));++cases;}printf("passed_cases=%u per_uid_limit=500 total_limit=4500\n",cases);}
''';(O/'test.cpp').write_text(code);cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all',str(O/'test.cpp'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr and x.stdout=='passed_cases=81 per_uid_limit=500 total_limit=4500\n',(x.returncode,x.stdout,x.stderr)
paths=[Path(__file__),src,jar,javap,source,header,O/'test.cpp'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'generated_uid_migration_enabled':True,'compiled_flags_accessor_constant_true':True,'actual_A17_budget_cases':81,'per_uid_limit':500,'total_limit':4500,'comparison_is_strict_greater_than':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'flags_changed':False,'provider_initialized':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual generated and compiled migration flag=true')
