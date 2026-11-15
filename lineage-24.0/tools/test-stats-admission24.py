#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test actual durable consumer, backend admission, factory lock ordering and NSS cleanup bodies.

Android-only APIs, store, Binder/kernel and service collaborators are explicit
host fixtures. No device execution or complete service-constructor test is claimed.
"""
import argparse,fcntl,hashlib,json,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','removal-reference','framework-reference','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();R=a.removal_reference.resolve();F=a.framework_reference.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
def write(n,text):q=O/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_text(text)
r=json.loads(a.native_report.read_text());old=json.loads((R/'report.json').read_text());fr=json.loads((F/'report.json').read_text())
assert r['passed'] and r['actual_durable_UID_intent_and_private_NSS_routing_compiled'] and old['passed'] and old['durable_removal_cases']==62 and fr['passed']
for n,h in {**old['source_hashes'],**fr['inputs_sha256'],**r['inputs_sha256']}.items():assert sha(Path(n))==h,n
for f in R.rglob('*.java'):
 q=O/f.relative_to(R);q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,q)
for f in (F/'classes').rglob('*.class'):bind(f)
for n in ['android/os/Process.java','com/android/modules/utils/build/SdkLevel.java','android/os/ServiceSpecificException.java','android/util/Pair.java']:
 f=F/n;bind(f);s=f.read_text()
 if n.endswith('/Process.java'):s=s.replace('public class Process {','public class Process {public static final int SYSTEM_UID=1000;')
 if n.endswith('/SdkLevel.java'):s=s.replace('public class SdkLevel {','public class SdkLevel {public static boolean isAtLeastV(){return true;}')
 write(n,s)
f=O/'android/system/OsConstants.java';s=f.read_text().replace('public class OsConstants{','public class OsConstants{public static final int EINVAL=22,ENODEV=19,ENOSPC=28,EOPNOTSUPP=95,ENOTCONN=107,EPROTO=71;');f.write_text(s)
# Assert the actual factory releases its existing lock before policy admission.
f=O/'com/android/server/BpfNetMaps.java';s=f.read_text().replace('public int admissions;', 'public Object factoryLock;public int admissions;').replace('admissions++;','if(factoryLock!=null&&Thread.holdsLock(factoryLock))throw new AssertionError("Factory lock held during policy admission");admissions++;');f.write_text(s)
f=O/'FactoryTest.java';s=f.read_text();needle='Path dir=Files.createDirectory';s=s.replace(needle,'java.lang.reflect.Field dataLock=NetworkStatsFactory.class.getDeclaredField("mPersistentDataLock");dataLock.setAccessible(true);maps.factoryLock=dataLock.get(factory);\n  '+needle,1);s=s.replace('factory.initializePrivateStats(dir.toFile());','factory.initializePrivateStats(dir.toFile());check(maps.admissions==1);',1);f.write_text(s)
# Use exact current factory body; only JNI library loading is a host boundary.
f=S/'java/com/android/server/net/NetworkStatsFactory.java';s=f.read_text();jni='    static {\n        System.loadLibrary("service-connectivity");\n    }';assert s.count(jni)==1;write('com/android/server/net/NetworkStatsFactory.java',s.replace(jni,'    // Explicit host JNI-loading boundary.'));bind(f)
f=S/'java/com/android/server/net/NetworkStatsService.java';service=f.read_text();bind(f)
start=service.index('private void removeUidsLocked(int... uids)');opening=service.index('{',start);depth=1;end=opening+1
while depth:depth+=(service[end]=='{')-(service[end]=='}');end+=1
method=service[start:end]
write('NssMethods.java','''import java.util.*;import java.io.*;
class NssMethods {
 static final boolean LOGV=false;static final String TAG="fixture";static final int FLAG_PERSIST_ALL=1,POLL_REASON_REMOVE_UIDS=2;
 Object mGtaStats=new Object();int failUid=-1;List<String>events=new ArrayList<>();
 static class Log{static void v(String t,String m){}static void e(String t,String m,Exception e){}}
 class Factory{void removePrivateUidAccounting(int[]uids)throws IOException{if(uids.length!=1)throw new AssertionError("Expected per-UID transaction");for(int uid:uids){events.add("native"+uid);if(uid==failUid)throw new IOException("Explicit unconfirmed mutation");}}void removeUidsLocked(int[]u){events.add("stockFactory");}}
 class Recorder{String name;Recorder(String n){name=n;}void removeUidsLocked(int[]u){for(int uid:u)events.add(name+uid);}}
 class Cache{void delete(int uid){events.add("cache"+uid);}}
 Factory mStatsFactory=new Factory();Recorder mUidRecorder=new Recorder("uid"),mUidTagRecorder=new Recorder("tag");Cache mActiveUidCounterSet=new Cache();
 void performPollLocked(int flags,Object event){events.add("poll");}Object maybeCreatePollEvent(int why){return null;}
 void deleteKernelTagData(int uid){events.add("stockKernel"+uid);}void test(int...uids){removeUidsLocked(uids);}
'''+method+'\n}')
write('AdmissionTest.java','import com.android.server.*;import com.android.server.permission.*;import android.util.*;import android.os.*;import java.util.*;\npublic class AdmissionTest {\n static int cases;static void check(boolean x){if(!x)throw new AssertionError("admission case "+cases);cases++;}\n interface Action{void run()throws Exception;}static void rejected(int code,Action a)throws Exception{try{a.run();throw new AssertionError();}catch(ServiceSpecificException e){check(e.errorCode==code);}}\n static class Transport implements Gta3xlwifiNetpolicyBackend.Transport {\n  int commits,aborts;long generation;boolean fail;Gta3xlwifiStatsAccess stats;Gta3xlwifiNetpolicyClient.Frame last;\n  Transport()throws Exception{stats=Test.live(new ConsumerTest.Remote(new ArrayList<>())).statsAccess();}\n  public boolean requiresStatsAdmission(){return true;}public Gta3xlwifiStatsAccess statsAccess(){return stats;}\n  public long publish(Gta3xlwifiNetpolicyClient.Frame f)throws RemoteException{commits++;last=f;if(fail)throw new RemoteException("explicit publish fault");return ++generation;}\n  public long generation(){return generation;}public void close(){aborts++;}public void abort(){aborts++;}\n }\n static void permissions(PermissionBpfMap r){SparseIntArray bits=new SparseIntArray();bits.put(0,1023);bits.put(1000,1023);bits.put(10001,4);r.setInitialUidPermissions(new int[]{0},new int[]{10001},bits);}\n public static void main(String[]args)throws Exception{\n  RemovalTest.main(args);\n  {Transport t=new Transport();var b=new Gta3xlwifiNetpolicyBackend(t,true,true,true);var r=b.permissionReceiver(true);permissions(r);b.setChain(1,true);b.setRule(1,10001,1);b.dataSaver(true);check(t.commits==0);rejected(11,()->b.permissions(10001));b.completeStatsAdmission();check(t.commits==1&&t.aborts==0&&b.rule(1,10001)==1);java.lang.reflect.Field f=t.last.getClass().getDeclaredField("mDataSaver");f.setAccessible(true);check((boolean)f.get(t.last));b.completeStatsAdmission();check(t.commits==1);b.setChain(1,false);check(t.commits==2);}\n  {Transport t=new Transport();var b=new Gta3xlwifiNetpolicyBackend(t,true,true,true);b.completeStatsAdmission();check(t.commits==0);permissions(b.permissionReceiver(true));check(t.commits==1);}\n  {Transport t=new Transport();ConsumerTest.Remote remote=new ConsumerTest.Remote(new ArrayList<>());remote.cleanupReceipt=new long[]{1,5,1,10001,7,1,2};t.stats=Test.live(remote).statsAccess();var b=new Gta3xlwifiNetpolicyBackend(t,true,true,true);permissions(b.permissionReceiver(true));rejected(107,b::completeStatsAdmission);check(t.commits==0&&t.aborts==1);rejected(107,()->b.permissions(10001));}\n  {Transport t=new Transport();t.fail=true;var b=new Gta3xlwifiNetpolicyBackend(t,true,true,true);permissions(b.permissionReceiver(true));rejected(107,b::completeStatsAdmission);check(t.commits==1&&t.aborts==1);rejected(107,()->b.permissions(10001));}\n  {NssMethods n=new NssMethods();n.test(10001,10002);check(n.events.equals(List.of("poll","native10001","uid10001","tag10001","cache10001","native10002","uid10002","tag10002","cache10002")));}\n  {NssMethods n=new NssMethods();n.failUid=10002;n.test(10001,10002,10003);check(n.events.equals(List.of("poll","native10001","uid10001","tag10001","cache10001","native10002","native10003","uid10003","tag10003","cache10003")));}\n  {NssMethods n=new NssMethods();n.failUid=10001;n.test(10001);check(n.events.equals(List.of("poll","native10001")));}\n  {NssMethods n=new NssMethods();n.mGtaStats=null;n.test(10001);check(n.events.equals(List.of("poll","uid10001","tag10001","stockFactory","stockKernel10001")));}\n  System.out.println("admission_service_cases="+cases);\n }\n}\n')
sources=[S/'java/com/android/server'/n for n in ['Gta3xlwifiNetpolicyClient.java','Gta3xlwifiStatsAccess.java','Gta3xlwifiStatsJournal.java','Gta3xlwifiStatsPoller.java','Gta3xlwifiStatsConsumer.java','Gta3xlwifiTrafficStats.java','Gta3xlwifiNetpolicyBackend.java','Gta3xlwifiPermissionCollector.java']]
for f in sources:assert sha(f)==r['inputs_sha256'][str(f)];bind(f)
for f in [Path(__file__),a.native_report,R/'report.json',F/'report.json']:bind(f)
cp=str(F/'classes');fc=fr['java_command']
if '-classpath' in fc:cp+=':'+fc[fc.index('-classpath')+1]
for entry in cp.split(':'):
 f=Path(entry)
 if f.is_file():bind(f)
javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';cmd=[str(javac),'-source','21','-target','21','-classpath',cp,'-d',str(O/'classes'),*map(str,sources),*map(str,O.rglob('*.java'))]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(javac.with_name('java')),'-ea','-cp',str(O/'classes')+':'+cp,'AdmissionTest'],capture_output=True,text=True,timeout=90);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
for f in O.rglob('*.java'):bind(f)
for n,h in inputs.items():assert sha(Path(n))==h
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'admission_service_cases':int(re.search(r'admission_service_cases=(\d+)',x.stdout)[1]),'prior_durable_removal_cases_replayed':62,'actual_backend_and_collector':True,'actual_factory_admission_outside_data_lock':True,'actual_NSS_cleanup_body_per_UID_partial_failure':True,'inputs_sha256':inputs,'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
