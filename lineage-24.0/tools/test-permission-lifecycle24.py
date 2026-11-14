#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual Kotlin registration/identity-refresh bodies with ordered mutation fixtures.

Permission state/package collections and raw bits are fixtures. Runs the actual
new Java default interface and unchanged Kotlin registration body; not Android
service, Binder, kernel or networking execution.
"""
import argparse,hashlib,json,os,re,subprocess,xml.etree.ElementTree as ET
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=json.loads(a.native_report.read_text());assert r['passed'] and r['actual_Kotlin_sources']==71 and r['original_class_inventory_preserved'];interface=a.native_report.parent/'permission-snapshot-interface.jar'
def extract(text,signature):
 start=text.index(signature);body=text.index('{',start);depth=1;i=body+1
 while depth:
  depth+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[start:i]
production=(S/'PermissionService.kt').read_text()
extra_helpers='\n'.join(extract(production,s) for s in ['private fun getBpfMapIdentityMetadata(', 'private fun sendBpfMapIdentitySnapshot(', 'private fun refreshBpfMapIdentitySnapshots(', 'fun unregisterBpfMap('])
assert production.index('refreshBpfMapIdentitySnapshots()',production.index('override fun onStateMutated()'))<production.index('addedUserIds.forEachIndexed',production.index('override fun onStateMutated()'))
new=extract((S/'PermissionService.kt').read_text(),'fun registerBpfMap(');old=extract((S/'PermissionService.kt.reference').read_text(),'fun registerBpfMap(')
access=(S/'AccessCheckingService.kt').read_text();helper=extract(access,'internal fun <T> withPermissionStateLock(')
xml=ET.parse(a.native_report.parent/'kotlinc-build.xml');cp=[x.get('path') for x in xml.getroot().iter('classpath')]
java=O/'android/util/SparseIntArray.java';java.parent.mkdir(parents=True);java.write_text('package android.util; public class SparseIntArray { private final java.util.TreeMap<Integer,Integer> data=new java.util.TreeMap<>(); public void put(int k,int v){data.put(k,v);} public int get(int k){return data.getOrDefault(k,0);} public int size(){return data.size();} public int keyAt(int i){return (int)data.keySet().toArray()[i];} public int valueAt(int i){return data.get(keyAt(i));} }\n')
classes=O/'java-classes';classes.mkdir();javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';java_cmd=[str(javac),'-d',str(classes),str(java)];x=subprocess.run(java_cmd,capture_output=True,text=True);assert x.returncode==0,x.stderr
code=r'''
import com.android.server.permission.PermissionBpfMap
import android.util.SparseIntArray
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.Collections
import kotlin.concurrent.thread
fun <T> List<T>.allIndexed(predicate:(Int,T)->Boolean):Boolean {for(i in indices)if(!predicate(i,this[i]))return false;return true}
typealias ArrayMap<K,V> = java.util.LinkedHashMap<K,V>
fun <K,V> Map<K,V>.forEachIndexed(block:(Int,K,V)->Unit){entries.forEachIndexed{i,e->block(i,e.key,e.value)}}
class MutableIntSet { private val data=linkedSetOf<Int>();val size get()=data.size;operator fun plusAssign(v:Int){data.add(v)};fun forEachIndexed(block:(Int,Int)->Unit){data.forEachIndexed(block)} }
object UserHandle { fun getUid(user:Int,app:Int)=user*100000+app }
class Users(val ids:List<Int>){val size get()=ids.size;fun forEachIndexed(block:(Int,Int,Unit)->Unit){ids.forEachIndexed{i,u->block(i,u,Unit)}}}
data class UserPackage(val isInstalled:Boolean)
class PackageState(val appId:Int,val isApex:Boolean,val installed:Set<Int>){fun getUserStateOrDefault(id:Int)=UserPackage(id in installed)}
class External(val packageStates:Map<String,PackageState>)
data class State(val raw:Int,val userStates:Users,val externalState:External)
class Scope(val state:State)
class AccessCheckingService(@Volatile var state:State){
 private val stateLock=Any()
'''+helper+r'''
 fun <T> getState(action:Scope.()->T)=Scope(state).action()
 fun mutate(raw:Int,callback:(State)->Unit){synchronized(stateLock){state=state.copy(raw=raw);callback(state)}}
}
class PermissionService(val service:AccessCheckingService,val ordered:Boolean){
 val bpfMapPermissionNamesLock=Any()
 @Volatile var bpfMapPermissionNames=ArrayMap<PermissionBpfMap,List<String>>()
 val bpfMapUserIds=ArrayMap<PermissionBpfMap,IntArray>()
 val bpfMapKnownUids=ArrayMap<PermissionBpfMap,IntArray>()
 val MAX_ALLOWED_BPF_PERMISSIONS=32
 val ALLOWED_BPF_PERMISSIONS=(0..9).map{"P$it"}.toSet()
 var snapshotHook:(()->Unit)?=null
 fun getBpfMapUidsPermissionBits(names:List<String>):SparseIntArray{val bits=service.getState {SparseIntArray().apply {if(state.raw!=0)put(10001,state.raw);state.userStates.ids.forEach{put(UserHandle.getUid(it,0),(1 shl names.size)-1);put(UserHandle.getUid(it,1000),(1 shl names.size)-1)}}};snapshotHook?.invoke();return bits}
'''+extra_helpers+'\n'+new.replace('fun registerBpfMap(','fun registerNew(',1)+'\n'+old.replace('fun registerBpfMap(','fun registerOld(',1)+r'''
 fun refreshForTest(){refreshBpfMapIdentitySnapshots()}
 fun register(map:PermissionBpfMap,names:List<String>){if(ordered)registerNew(map,names)else registerOld(map,names)}
 fun mutate(raw:Int){service.mutate(raw){s->if(ordered)refreshBpfMapIdentitySnapshots();val bits=SparseIntArray();bits.put(10001,s.raw);bpfMapPermissionNames.keys.forEach{it.setUidsPermissionBits(bits)}}}
}
fun PermissionService.replaceIdentity(users:List<Int> = service.state.userStates.ids, packages:Map<String,PackageState> = service.state.externalState.packageStates){service.withPermissionStateLock{service.state=service.state.copy(userStates=Users(users),externalState=External(packages));refreshNow()}}
fun PermissionService.refreshNow(){service.withPermissionStateLock{refreshForTest()}}
class Receiver:PermissionBpfMap{
 val values=Collections.synchronizedList(mutableListOf<Int>())
 var users:IntArray?=null;var known:IntArray?=null;var fail=false;var snapshots=0
 override fun setUidsPermissionBits(bits:SparseIntArray){if(fail)error("callback failed");values.add(bits.get(10001))}
 override fun setInitialUidPermissions(u:IntArray,k:IntArray,bits:SparseIntArray){snapshots++;users=u;known=k;setUidsPermissionBits(bits)}
 override fun removeAppId(id:Int){};override fun removeUser(id:Int){}
}
class OldReceiver:PermissionBpfMap{var calls=0;var bits:SparseIntArray?=null;override fun setUidsPermissionBits(b:SparseIntArray){calls++;bits=b};override fun removeAppId(id:Int){};override fun removeUser(id:Int){}}
fun fixture(ordered:Boolean):PermissionService{val pkgs=linkedMapOf("a" to PackageState(10001,false,setOf(0,10)),"shared" to PackageState(10001,false,setOf(0,10)),"no-perm" to PackageState(10002,false,setOf(0)),"other-user" to PackageState(10003,false,setOf(10)),"apex" to PackageState(11000,true,setOf(0,10)));return PermissionService(AccessCheckingService(State(4,Users(listOf(0,10)),External(pkgs))),ordered)}
val names=(0..9).map{"P$it"}
fun await(l:CountDownLatch){check(l.await(10,TimeUnit.SECONDS))}
fun main(){var cases=0
 // Pin the old registration bug deterministically: newer revoke, then old grant.
 run{val p=fixture(false);val receiver=Receiver();val captured=CountDownLatch(1);val release=CountDownLatch(1);p.snapshotHook={captured.countDown();await(release)};val reader=thread{p.register(receiver,names)};await(captured);p.mutate(0);release.countDown();reader.join();check(receiver.values==listOf(0,4));cases++}
 repeat(50){val p=fixture(true);val receiver=Receiver();val captured=CountDownLatch(1);val release=CountDownLatch(1);val attempting=CountDownLatch(1);p.snapshotHook={captured.countDown();await(release)};val reader=thread{p.register(receiver,names)};await(captured);val writer=thread{attempting.countDown();p.mutate(0)};await(attempting);check(receiver.values.isEmpty());release.countDown();reader.join();writer.join();check(receiver.values==listOf(4,0));check(receiver.users!!.toSet()==setOf(0,10));check(receiver.known!!.toSet()==setOf(10001,10002,1010001,1010003));check(receiver.known!!.size==4);cases++}
 run{val p=fixture(true);val old=OldReceiver();p.register(old,names);check(old.calls==1&&old.bits!!.get(10001)==4&&old.bits!!.get(0)==1023&&old.bits!!.get(1000)==1023&&old.bits!!.get(1000000)==1023&&old.bits!!.get(1001000)==1023);p.mutate(0);check(old.calls==2&&old.bits!!.get(10001)==0);cases++}
 run{val p=fixture(true);val receiver=Receiver();receiver.fail=true;check(runCatching{p.register(receiver,names)}.isFailure);check(p.bpfMapPermissionNames.isEmpty());receiver.fail=false;p.mutate(0);check(receiver.values.isEmpty());p.register(receiver,names);check(receiver.values==listOf(0));cases++}
 repeat(25){val p=fixture(true);val receiver=Receiver();val successes=AtomicInteger();val failures=AtomicInteger();val start=CountDownLatch(1);val work={await(start);try{p.register(receiver,names);successes.incrementAndGet()}catch(expected:IllegalArgumentException){failures.incrementAndGet()};Unit};val a=thread(block=work);val b=thread(block=work);start.countDown();a.join();b.join();check(successes.get()==1&&failures.get()==1&&receiver.values==listOf(4));cases++}
 for(bad in listOf(emptyList(),listOf("unknown"),List(33){"P0"})){val p=fixture(true);check(runCatching{p.register(Receiver(),bad)}.isFailure&&p.bpfMapPermissionNames.isEmpty());cases++}

 // Identity changes with no raw permission event still produce a complete frame before deltas.
 run{val p=fixture(true);val r=Receiver();p.register(r,names);check(r.snapshots==1);p.refreshNow();check(r.snapshots==1)
  var pkgs=p.service.state.externalState.packageStates+mapOf("new-zero" to PackageState(10004,false,setOf(0)))
  p.replaceIdentity(packages=pkgs);check(r.snapshots==2&&10004 in r.known!!&&r.values.last()==4)
  pkgs=pkgs+mapOf("another-shared" to PackageState(10001,false,setOf(0)),"not-installed" to PackageState(10005,false,emptySet()),"new-apex" to PackageState(10006,true,setOf(0)))
  p.replaceIdentity(packages=pkgs);check(r.snapshots==2)
  pkgs=pkgs+mapOf("new-zero" to PackageState(10004,false,setOf(0,2)))
  p.replaceIdentity(users=listOf(10,2,0),packages=pkgs);check(r.snapshots==3&&r.users!!.toList()==listOf(0,2,10)&&210004 in r.known!!)
  check(p.bpfMapKnownUids[r]!!.toList()==r.known!!.toList());p.replaceIdentity(users=listOf(2,0),packages=pkgs-"no-perm");check(r.snapshots==4&&r.users!!.toList()==listOf(0,2)&&10002 !in r.known!!)
  p.unregisterBpfMap(r);check(r !in p.bpfMapPermissionNames&&r !in p.bpfMapUserIds&&r !in p.bpfMapKnownUids);val calls=r.snapshots;p.replaceIdentity(users=listOf(0));check(r.snapshots==calls);p.register(r,names);check(r.snapshots==calls+1);cases++}
 // Receiver mutation of arrays cannot mutate the per-consumer metadata cache.
 run{val p=fixture(true);var calls=0;val r=object:PermissionBpfMap{override fun setUidsPermissionBits(bits:SparseIntArray){};override fun setInitialUidPermissions(u:IntArray,k:IntArray,bits:SparseIntArray){calls++;u.fill(-1);k.fill(-2)};override fun removeAppId(id:Int){};override fun removeUser(id:Int){}}
 p.register(r,names);check(p.bpfMapUserIds[r]!!.toList()==listOf(0,10)&&p.bpfMapKnownUids[r]!!.all{it>=0});p.refreshNow();check(calls==1);cases++}
 // Registering a second consumer cannot conceal a metadata change from the first.
 run{val p=fixture(true);val first=Receiver();p.register(first,names);p.service.withPermissionStateLock{p.service.state=p.service.state.copy(externalState=External(p.service.state.externalState.packageStates+mapOf("fresh" to PackageState(10007,false,setOf(0)))))}
 val second=Receiver();p.register(second,names);check(first.snapshots==1&&second.snapshots==1);p.refreshNow();check(first.snapshots==2&&second.snapshots==1&&10007 in first.known!!);cases++}
 // A failed callback cannot advance its identity epoch. The next explicit refresh retries it.
 run{val p=fixture(true);val r=Receiver();p.register(r,names);val before=p.bpfMapKnownUids[r]!!.clone();r.fail=true;check(runCatching{p.replaceIdentity(packages=p.service.state.externalState.packageStates+mapOf("fresh" to PackageState(10008,false,setOf(0))))}.isFailure);check(p.bpfMapKnownUids[r]!!.contentEquals(before));r.fail=false;p.refreshNow();check(10008 in p.bpfMapKnownUids[r]!!&&r.snapshots==3);cases++}
 // Old consumers receive real complete raw updates through the default callback.
 run{val p=fixture(true);val r=OldReceiver();p.register(r,names);p.replaceIdentity(users=listOf(0,10,2));check(r.calls==2&&r.bits!!.get(200000)==1023&&r.bits!!.get(201000)==1023);cases++}
 // Unregister is a fence after the in-flight initial callback and removes all cached identity state.
 repeat(10){val p=fixture(true);val r=Receiver();val captured=CountDownLatch(1);val release=CountDownLatch(1);val attempting=CountDownLatch(1);val removed=CountDownLatch(1);p.snapshotHook={captured.countDown();await(release)};val registration=thread{p.register(r,names)};await(captured);val removal=thread{attempting.countDown();p.unregisterBpfMap(r);removed.countDown()};await(attempting);check(removed.count==1L);release.countDown();registration.join();removal.join();p.snapshotHook=null;val count=r.snapshots;p.replaceIdentity(users=listOf(0));check(r.snapshots==count&&p.bpfMapKnownUids.isEmpty()&&p.bpfMapUserIds.isEmpty());cases++}
 println("passed_cases=$cases ordered_races=50 duplicate_races=25 old_race_reproduced=true")
}
''';kt=O/'Test.kt';kt.write_text(code)
kotlinc=T/'external/kotlinc/bin/kotlinc';command=[str(kotlinc),'-jvm-target','21','-classpath',os.pathsep.join([str(classes),str(interface),*cp]),str(kt),'-d',str(O/'test.jar')]
x=subprocess.run(command,cwd=T,capture_output=True,text=True,env={**os.environ,'JAVA_HOME':str(T/'prebuilts/jdk/jdk21/linux-x86')});(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
run=[str(T/'prebuilts/jdk/jdk21/linux-x86/bin/java'),'-ea','-cp',os.pathsep.join([str(O/'test.jar'),str(classes),str(interface),str(T/'external/kotlinc/lib/kotlin-stdlib.jar')]),'TestKt'];x=subprocess.run(run,capture_output=True,text=True,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+) ordered_races=50 duplicate_races=25 old_race_reproduced=true\n',x.stdout);assert m
paths=[Path(__file__),S/'PermissionService.kt',S/'PermissionService.kt.reference',S/'AccessCheckingService.kt',S/'PermissionBpfMap.java',a.native_report,interface,kt,java]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'ordered_races':50,'duplicate_registration_races':25,'old_revocation_overwrite_reproduced':True,'same_epoch_users_installed_shared_no_permission_apex_metadata_checked':True,'old_default_callback_compatible':True,'failed_initial_callback_unregistered':True,'identity_change_before_deltas_checked':True,'per_consumer_epoch_isolation':True,'mutated_consumer_arrays_isolated':True,'unregister_callback_fence_races':10,'inputs_sha256':{str(p):sha(p) for p in paths},'compile_command':command,'run_command':run,'framework_runtime_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
