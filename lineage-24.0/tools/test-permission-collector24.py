#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual Java raw receiver with pinned Android UID/SDK functions and sink fixtures.

Tests callback ordering/values and invalidation, not real observer registration,
Binder, native HOLD, packets or framework networking readiness.
"""
import argparse,fcntl,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','permission-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();n=json.loads(a.native_report.read_text());assert n['passed'];source=S/'java/com/android/server/Gta3xlwifiPermissionCollector.java';assert sha(source)==n['inputs_sha256'][str(source)]
interface=a.permission_report.parent/'permission-snapshot-interface.jar'
def put(path,text):p=O/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
def extract(text,signature):
 start=text.index(signature);body=text.index('{',start);depth=1;i=body+1
 while depth:depth+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[start:i]
process=T/'frameworks/base/core/java/android/os/Process.java';user=T/'frameworks/base/core/java/android/os/UserHandle.java';monitor=T/'packages/modules/Connectivity/service/src/com/android/server/connectivity/PermissionMonitor.java';ps=process.read_text();us=user.read_text();ms=monitor.read_text()
constants={name:int(re.search(r'\b'+name+r'\s*=\s*(\d+);',ps)[1]) for name in ['FIRST_APPLICATION_UID','LAST_APPLICATION_UID','FIRST_SDK_SANDBOX_UID']}
assert constants=={'FIRST_APPLICATION_UID':10000,'LAST_APPLICATION_UID':19999,'FIRST_SDK_SANDBOX_UID':20000}
assert 'return SdkLevel.isAtLeastT() && Process.isApplicationUid(uid);' in extract(ms,'private static boolean hasSdkSandbox(')
assert len(re.findall(r'public static final int PERMISSION_BPF_MAP_BIT_\w+\s*=',ms))==10
put('android/os/Process.java','package android.os; public class Process {\n'+'\n'.join('public static final int '+k+'='+str(v)+';' for k,v in constants.items())+'\n'+extract(ps,'public static boolean isApplicationUid(')+'\n'+extract(ps,'public static final int toSdkSandboxUid(')+'\n}')
put('android/os/UserHandle.java','package android.os; public class UserHandle { public static final int PER_USER_RANGE=100000;\n'+extract(us,'public static boolean isApp(')+'\n'+extract(us,'public static @AppIdInt int getAppId(').replace('@AppIdInt ', '')+'\n}')
put('com/android/modules/utils/build/SdkLevel.java','package com.android.modules.utils.build; public class SdkLevel { public static boolean enabled=true; public static boolean isAtLeastT(){return enabled;} }')
put('android/util/SparseIntArray.java','package android.util; public class SparseIntArray {private final java.util.TreeMap<Integer,Integer> data=new java.util.TreeMap<>();public void put(int k,int v){data.put(k,v);}public int size(){return data.size();}public int keyAt(int i){return (int)data.keySet().toArray()[i];}public int valueAt(int i){return data.get(keyAt(i));}}')
put('Test.java',r'''
import android.util.SparseIntArray;
import com.android.server.Gta3xlwifiPermissionCollector;
import com.android.server.Gta3xlwifiPermissionCollector.Snapshot;
import com.android.modules.utils.build.SdkLevel;
import java.util.*;
public class Test {
 static int cases;
 static void check(boolean v){if(!v)throw new AssertionError("case "+cases);cases++;}
 interface Action{void run();}
 static void rejected(Action a){try{a.run();throw new AssertionError("missing failure");}catch(RuntimeException expected){cases++;}}
 static SparseIntArray bits(int... values){SparseIntArray b=new SparseIntArray();for(int i=0;i<values.length;i+=2)b.put(values[i],values[i+1]);return b;}
 static SparseIntArray initial(int appBits){return bits(0,1023,1000,1023,1000000,1023,1001000,1023,10001,appBits,1010001,0);}
 static Map<Integer,Integer> raw(Snapshot s){int[]v=s.rawPermissionWords();Map<Integer,Integer>r=new TreeMap<>();for(int i=0;i<v.length;i+=2)r.put(v[i],v[i+1]);return r;}
 static Set<Integer> known(Snapshot s){Set<Integer>r=new TreeSet<>();for(int uid:s.knownUids())r.add(uid);return r;}
 static class Sink implements Gta3xlwifiPermissionCollector.Sink {
  final Object lock;final List<Snapshot> accepted=new ArrayList<>();int stops;RuntimeException acceptFailure,stopFailure;boolean sameFailure;
  Sink(Object l){lock=l;}
  public void accept(Snapshot s){if(!Thread.holdsLock(lock))throw new AssertionError("sink lock");if(acceptFailure!=null)throw acceptFailure;accepted.add(s);}
  public void invalidate(Throwable cause){if(!Thread.holdsLock(lock))throw new AssertionError("invalidation lock");stops++;if(sameFailure)throw (RuntimeException)cause;if(stopFailure!=null)throw stopFailure;}
 }
 static class Fixture {final Object lock=new Object();final Sink sink=new Sink(lock);final Gta3xlwifiPermissionCollector c=new Gta3xlwifiPermissionCollector(lock,sink);void initialize(){c.setInitialUidPermissions(new int[]{10,0},new int[]{10001,10002,10001,1010001},initial(4));}}
 public static void main(String[]args)throws Exception{
  {Fixture f=new Fixture();rejected(()->f.c.setUidsPermissionBits(bits(10001,4)));check(f.sink.stops==1&&f.sink.accepted.isEmpty());rejected(f.c::snapshot);f.initialize();check(Arrays.equals(f.c.snapshot().users(),new int[]{0,10}));check(known(f.c.snapshot()).equals(Set.of(10001,10002,20001,20002,1010001,1020001)));Map<Integer,Integer> r=raw(f.c.snapshot());check(r.get(10001)==4&&r.get(20001)==4&&r.get(1010001)==0&&r.get(1020001)==0&&!r.containsKey(10002));
   Snapshot before=f.c.snapshot();before.users()[0]=99;before.knownUids()[0]=-1;before.rawPermissionWords()[1]=-1;check(f.c.snapshot().users()[0]==0&&known(f.c.snapshot()).contains(10001)&&raw(f.c.snapshot()).get(0)==1023);
   f.c.setUidsPermissionBits(bits(10001,0));check(raw(f.c.snapshot()).get(10001)==0&&raw(f.c.snapshot()).get(20001)==0);check(raw(before).get(10001)==4);
   f.c.removeAppId(10001);check(!known(f.c.snapshot()).contains(10001)&&!known(f.c.snapshot()).contains(20001)&&!known(f.c.snapshot()).contains(1010001)&&!raw(f.c.snapshot()).containsKey(1020001));check(known(f.c.snapshot()).equals(Set.of(10002,20002)));
   f.initialize();f.c.removeUser(10);check(Arrays.equals(f.c.snapshot().users(),new int[]{0})&&!raw(f.c.snapshot()).containsKey(1000000)&&!known(f.c.snapshot()).contains(1020001));
   f.c.setInitialUidPermissions(new int[]{0},new int[]{10003},bits(0,1023,1000,1023,10003,4));check(known(f.c.snapshot()).equals(Set.of(10003,20003))&&!raw(f.c.snapshot()).containsKey(10001));
  }
  // Preserve every actual raw combination before native conversion; sandbox matches pinned A17.
  for(int value=0;value<1024;value++){Fixture f=new Fixture();f.c.setInitialUidPermissions(new int[]{0},new int[]{10001},bits(0,1023,1000,1023,10001,value));Map<Integer,Integer>r=raw(f.c.snapshot());check(r.get(10001)==value&&r.get(20001)==value);f.c.setUidsPermissionBits(bits(10001,value^1023));check(raw(f.c.snapshot()).get(20001)==(value^1023));}
  for(int uid:new int[]{9999,10000,19999,20000,109999,110000,119999,120000,2147410000,2147419999,Integer.MAX_VALUE}){
   int u=uid/100000;SparseIntArray b=bits(0,1023,1000,1023);int[]users=u==0?new int[]{0}:new int[]{0,u};if(u!=0){b.put(u*100000,1023);b.put(u*100000+1000,1023);}b.put(uid,4);Fixture f=new Fixture();f.c.setInitialUidPermissions(users,new int[]{uid},b);boolean app=android.os.Process.isApplicationUid(uid);check(known(f.c.snapshot()).contains(uid));if(app)check(known(f.c.snapshot()).contains(android.os.Process.toSdkSandboxUid(uid))&&raw(f.c.snapshot()).get(android.os.Process.toSdkSandboxUid(uid))==4);
  }
  SdkLevel.enabled=false;{Fixture f=new Fixture();f.initialize();check(known(f.c.snapshot()).equals(Set.of(10001,10002,1010001))&&!raw(f.c.snapshot()).containsKey(20001));}SdkLevel.enabled=true;
  // Malformed callback data synchronously invokes invalidation and requires a new complete frame.
  for(int part=0;part<14;part++){Fixture f=new Fixture();f.initialize();final int p=part;rejected(()->{switch(p){case 0:f.c.setInitialUidPermissions(new int[]{0,0},new int[]{},bits(0,1023,1000,1023));break;case 1:f.c.setInitialUidPermissions(new int[]{10},new int[]{},initial(4));break;case 2:f.c.setInitialUidPermissions(new int[]{0},new int[]{-1},initial(4));break;case 3:f.c.setInitialUidPermissions(new int[]{0},new int[]{110001},initial(4));break;case 4:f.c.setUidsPermissionBits(bits(10001,1024));break;case 5:f.c.setUidsPermissionBits(bits(-1,4));break;case 6:f.c.setUidsPermissionBits(bits(110001,4));break;case 7:f.c.setUidsPermissionBits(bits(10001,4,20001,0));break;case 8:f.c.setUidsPermissionBits(bits(0,0));break;case 9:f.c.removeAppId(0);break;case 10:f.c.removeAppId(100000);break;case 11:f.c.removeUser(0);break;case 12:f.c.setInitialUidPermissions(new int[65537],new int[]{},initial(4));break;case 13:f.c.setInitialUidPermissions(new int[]{0,Integer.MAX_VALUE},new int[]{},initial(4));break;}});check(f.sink.stops==1);rejected(f.c::snapshot);rejected(()->f.c.setUidsPermissionBits(bits(10001,4)));f.initialize();check(raw(f.c.snapshot()).get(10001)==4);}
  // Expanded identities must fail the native bound rather than silently truncate sandboxes.
  {Fixture f=new Fixture();int[]k=new int[40000];int n=0;SparseIntArray b=new SparseIntArray();for(int user=0;user<4;user++){b.put(user*100000,1023);b.put(user*100000+1000,1023);for(int app=10000;app<20000;app++)k[n++]=user*100000+app;}rejected(()->f.c.setInitialUidPermissions(new int[]{0,1,2,3},k,b));check(f.sink.stops==1);}
  {Fixture f=new Fixture();f.initialize();RuntimeException original=new IllegalStateException("publish"),cleanup=new IllegalStateException("cleanup");f.sink.acceptFailure=original;f.sink.stopFailure=cleanup;try{f.c.setUidsPermissionBits(bits(10001,0));throw new AssertionError();}catch(RuntimeException e){check(e==original&&e.getSuppressed().length==1&&e.getSuppressed()[0]==cleanup);}check(f.sink.stops==1);rejected(f.c::snapshot);f.sink.acceptFailure=null;f.sink.stopFailure=null;f.initialize();}
  {Fixture f=new Fixture();f.initialize();RuntimeException original=new IllegalStateException("same");f.sink.acceptFailure=original;f.sink.sameFailure=true;try{f.c.setUidsPermissionBits(bits(10001,0));throw new AssertionError();}catch(RuntimeException e){check(e==original&&e.getSuppressed().length==0);}check(f.sink.stops==1);}
  // Both ordinary cache access and callbacks use one caller-supplied lock.
  {Fixture f=new Fixture();f.initialize();List<Throwable>errors=Collections.synchronizedList(new ArrayList<>());Thread a=new Thread(()->{try{for(int i=0;i<100;i++)f.c.setUidsPermissionBits(bits(10001,i%2==0?4:0));}catch(Throwable e){errors.add(e);}});Thread b=new Thread(()->{try{for(int i=0;i<100;i++)synchronized(f.lock){f.c.snapshot();}}catch(Throwable e){errors.add(e);}});a.start();b.start();a.join();b.join();check(errors.isEmpty()&&f.sink.accepted.size()==101);for(Snapshot s:f.sink.accepted)check(raw(s).get(10001).equals(raw(s).get(20001)));}
  System.out.println("passed_cases="+cases);
 }
}
''')
classes=O/'classes';classes.mkdir();javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';cmd=[str(javac),'-source','21','-target','21','-classpath',str(interface),'-d',str(classes),str(source),*map(str,O.rglob('*.java'))]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(javac.with_name('java')),'-ea','-cp',str(classes)+os.pathsep+str(interface),'Test'],capture_output=True,text=True,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m
paths=[Path(__file__),source,a.native_report,a.permission_report,interface,process,user,monitor,*O.rglob('*.java')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'raw_permission_combinations':1024,'actual_pinned_Process_UserHandle_functions':True,'SDK_identity_expansion_checked':True,'sink_failure_invalidates_input':True,'one_shared_policy_lock':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'framework_observer_registered':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
