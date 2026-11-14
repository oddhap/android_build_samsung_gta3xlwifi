#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute actual DEFAULT branch and identity-only helper with cold/PM/state fixtures.

Source-body lifecycle evidence, not PackageManager/Android boot execution.
"""
import argparse,fcntl,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','base-source','native-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();B=a.base_source.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();report=json.loads(a.native_report.read_text());assert report['passed'] and report['class_count']==155
for name in ['PermissionService.kt','AccessCheckingService.kt']:
 assert sha(S/name)==report['inputs_sha256'][str(S/name)]
def extract(text,signature):
 start=text.index(signature);body=text.index('{',start);depth=1;i=body+1
 while depth:depth+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[start:i]
access=(S/'AccessCheckingService.kt').read_text();permission=(S/'PermissionService.kt').read_text()
helper=extract(access,'internal fun refreshPackageIdentityStateIfInitialized()')
branch=extract(permission,'if (params === PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT)')
added='            service.refreshPackageIdentityStateIfInitialized()\n'
assert permission.replace(added,'',1)==(B/'PermissionService.kt').read_text()
assert helper.index('if (!::state.isInitialized) return')<helper.index('packageManagerLocal.allPackageStates')<helper.index('mutateState {')
assert all(x not in helper for x in ['with(policy)','onPackageInstalled(','PermissionFlags','grantPermission','clearRestricted'])
installer=T/'frameworks/base/services/core/java/com/android/server/pm/InstallPackageHelper.java';install=installer.read_text()
assert 'permissionParamsBuilder.build(), userId);' in install and install.index('permissionParamsBuilder.build(), userId);')<install.index('mAppDataHelper.prepareAppDataPostCommitLIF(')
code=r'''
object PermissionManagerServiceInternal { class PackageInstalledParams {companion object {val DEFAULT=PackageInstalledParams()}} }
class External(var packages:Map<String,Int>,var disabled:Map<String,Int>,var known:Map<String,Int>){fun setPackageStates(value:Map<String,Int>){packages=value};fun setDisabledSystemPackageStates(value:Map<String,Int>){disabled=value};fun setKnownPackages(value:Map<String,Int>){known=value};fun copy()=External(packages,disabled,known)}
class State(val external:External,val flags:Map<String,Int>){fun mutateExternalState()=external}
class Scope(val newState:State)
class PM(var installed:Map<String,Int>,var disabled:Map<String,Int>){var calls=0;var fail=false;var verify:()->Unit={};val allPackageStates:Pair<Map<String,Int>,Map<String,Int>> get(){verify();calls++;if(fail)error("snapshot failure");return Pair(installed,disabled)}}
class Internal(var known:Map<String,Int>){var calls=0;var fail=false;var verify:()->Unit={};val knownPackages:Map<String,Int> get(){verify();calls++;if(fail)error("known failure");return known}}
class AccessCheckingService{
 private lateinit var state:State
 private lateinit var packageManagerLocal:PM
 private lateinit var packageManagerInternal:Internal
 private val stateLock=Any()
 var inMutation=false;var mutations=0;var notifications=0
 var observer:(State)->Unit={}
 fun initialize(s:State,p:PM,i:Internal){state=s;packageManagerLocal=p;packageManagerInternal=i;p.verify={check(!inMutation)};i.verify={check(!inMutation)}}
 fun value()=state
 fun mutateState(action:Scope.()->Unit){synchronized(stateLock){inMutation=true;val next=State(state.external.copy(),state.flags);try{Scope(next).action();state=next;mutations++;notifications++;observer(next)}finally{inMutation=false}}}
'''+helper+r'''
}
class PermissionService(val service:AccessCheckingService){var oldPolicyCalls=0;fun onPackageInstalled(params:PermissionManagerServiceInternal.PackageInstalledParams){
'''+branch+r'''
 oldPolicyCalls++
}}
fun main(){var cases=0
 fun pass(value:Boolean){check(value);cases++}
 val cold=AccessCheckingService();val wrapper=PermissionService(cold)
 wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT);pass(cold.mutations==0&&wrapper.oldPolicyCalls==0)
 wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams());pass(cold.mutations==0&&wrapper.oldPolicyCalls==1)
 val originalFlags=mapOf("UPGRADE_EXEMPT" to 1,"INTERNET" to 4,"NO_PERMISSIONS" to 0)
 val initial=State(External(mapOf("old" to 10001),emptyMap(),mapOf("role" to 10001)),originalFlags)
 val pm=PM(mapOf("new-zero" to 10002,"shared-a" to 10001,"shared-b" to 10001),mapOf("disabled" to 11000));val internal=Internal(mapOf("role" to 10001))
 cold.initialize(initial,pm,internal);var observed:State?=null;cold.observer={observed=it}
 wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT)
 pass(cold.mutations==1&&cold.notifications==1&&pm.calls==1&&internal.calls==1)
 pass(cold.value().external.packages==pm.installed&&cold.value().external.disabled==pm.disabled&&cold.value().external.known==internal.known)
 pass(cold.value().flags===originalFlags&&cold.value().flags["UPGRADE_EXEMPT"]==1&&cold.value().flags["NO_PERMISSIONS"]==0)
 pass(observed===cold.value()&&observed!!.external.packages["new-zero"]==10002)
 pass(initial.external.packages==mapOf("old" to 10001)&&wrapper.oldPolicyCalls==1)
 // A later DEFAULT install gets current identity with unchanged permission-policy flags.
 pm.installed=mapOf("next-zero" to 10003);internal.known=emptyMap();wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT)
 pass(cold.mutations==2&&cold.value().external.packages==mapOf("next-zero" to 10003)&&cold.value().flags===originalFlags)
 // Failed external reads cannot publish state or notify a fictitious complete snapshot.
 val before=cold.value();pm.fail=true;pass(runCatching{wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT)}.isFailure);pass(cold.value()===before&&cold.mutations==2&&cold.notifications==2)
 pm.fail=false;internal.fail=true;pass(runCatching{wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT)}.isFailure);pass(cold.value()===before&&cold.mutations==2&&cold.notifications==2)
 internal.fail=false;wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT);pass(cold.mutations==3&&cold.notifications==3&&cold.value().flags===originalFlags)
 println("passed_cases=$cases")
}
'''
kt=O/'Test.kt';kt.write_text(code);command=[str(T/'external/kotlinc/bin/kotlinc'),'-jvm-target','21',str(kt),'-d',str(O/'test.jar')]
x=subprocess.run(command,cwd=T,capture_output=True,text=True,env={**os.environ,'JAVA_HOME':str(T/'prebuilts/jdk/jdk21/linux-x86')});(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
run=[str(T/'prebuilts/jdk/jdk21/linux-x86/bin/java'),'-ea','-cp',str(O/'test.jar')+os.pathsep+str(T/'external/kotlinc/lib/kotlin-stdlib.jar'),'TestKt']
x=subprocess.run(run,capture_output=True,text=True,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m
paths=[Path(__file__),S/'AccessCheckingService.kt',S/'PermissionService.kt',B/'PermissionService.kt',a.native_report,installer,kt]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'original_nonDEFAULT_permission_logic_unchanged':True,'cold_start_guard_before_PM_fields':True,'no_PM_query_under_state_lock':True,'no_grants_or_restricted_exemption_changes':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':command,'framework_runtime_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
