#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run complete consumer with actual A17 NetworkStats/UnderlyingNetworkInfo algorithms.

Binder/kernel/store and Android-only API boundaries are explicit fixtures.
NetworkStats and VPN/464xlat adjustment code are copied byte-for-byte from TOP.
"""
import argparse,fcntl,hashlib,json,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','poll-reference','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();R=a.poll_reference.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads(a.native_report.read_text());old=json.loads((R/'report.json').read_text());assert r['passed'] and r['actual_terminal_session_token_abort_compiled'] and old['passed'] and old['poll_cases']==61
for n,h in old['inputs_sha256'].items():assert sha(Path(n))==h
for f in R.rglob('*.java'):
 q=O/f.relative_to(R);q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,q)
inputs=[Path(__file__),a.native_report,R/'report.json']
def write(n,text):
 q=O/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_text(text)
for n in ['NetworkStats','UnderlyingNetworkInfo']:
 f=T/('packages/modules/Connectivity/framework-t/src/android/net/'+n+'.java');inputs.append(f);q=O/('android/net/'+n+'.java');q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,q)
for n,body in {'NonNull':'','Nullable':'','FlaggedApi':'String value();','IntDef':'String[] prefix() default {}; long[] value() default {}; boolean flag() default false;','SystemApi':'Client client() default Client.PRIVILEGED_APPS; enum Client {PRIVILEGED_APPS,MODULE_LIBRARIES,SYSTEM_SERVER}'}.items():write('android/annotation/'+n+'.java','package android.annotation;public @interface '+n+'{'+body+'}')
write('android/compat/annotation/UnsupportedAppUsage.java','package android.compat.annotation;public @interface UnsupportedAppUsage {int maxTargetSdk() default 0;long trackingBug() default 0;}')
write('com/android/internal/annotations/VisibleForTesting.java','package com.android.internal.annotations;public @interface VisibleForTesting{}')
write('android/os/Build.java','package android.os;public class Build{public static class VERSION_CODES{public static final int R=30;}}')
write('android/os/Process.java','package android.os;public class Process{public static final int SYSTEM_UID=1000;}')
write('android/os/SystemClock.java','package android.os;public class SystemClock{public static long elapsedRealtime(){return 1000;}}')
write('android/os/Parcelable.java','package android.os;public interface Parcelable{int describeContents();void writeToParcel(Parcel p,int flags);interface Creator<T>{T createFromParcel(Parcel p);T[]newArray(int n);}}')
write('android/os/Parcel.java','''package android.os;public class Parcel{
 public long readLong(){throw new UnsupportedOperationException();}public int readInt(){throw new UnsupportedOperationException();}public String readString(){throw new UnsupportedOperationException();}
 public String[]createStringArray(){throw new UnsupportedOperationException();}public int[]createIntArray(){throw new UnsupportedOperationException();}public long[]createLongArray(){throw new UnsupportedOperationException();}
 public void writeLong(long x){throw new UnsupportedOperationException();}public void writeInt(int x){throw new UnsupportedOperationException();}public void writeString(String x){throw new UnsupportedOperationException();}
 public void writeStringArray(String[]x){throw new UnsupportedOperationException();}public void writeIntArray(int[]x){throw new UnsupportedOperationException();}public void writeLongArray(long[]x){throw new UnsupportedOperationException();}
 public void writeList(java.util.List<?>x){throw new UnsupportedOperationException();}public <T>void readList(java.util.List<T>x,ClassLoader c,Class<T>t){throw new UnsupportedOperationException();}}
''')
write('android/text/TextUtils.java','package android.text;public class TextUtils{public static boolean equals(CharSequence a,CharSequence b){return java.util.Objects.equals(a,b);}}')
write('android/util/SparseBooleanArray.java','package android.util;public class SparseBooleanArray{private final java.util.TreeMap<Integer,Boolean>m=new java.util.TreeMap<>();public void put(int k,boolean v){m.put(k,v);}public boolean get(int k){return m.getOrDefault(k,false);}public int size(){return m.size();}public int keyAt(int i){return new java.util.ArrayList<>(m.keySet()).get(i);}}')
write('com/android/modules/utils/build/SdkLevel.java','package com.android.modules.utils.build;public class SdkLevel{public static boolean isAtLeastV(){return true;}}')
write('com/android/net/flags/Flags.java','package com.android.net.flags;public class Flags{public static final String FLAG_NETSTATS_ADD_ENTRIES="fixture";}')
write('com/android/net/module/util/CollectionUtils.java','package com.android.net.module.util;public class CollectionUtils{public static <T>boolean contains(T[]a,T v){if(a==null)return false;for(T x:a)if(java.util.Objects.equals(x,v))return true;return false;}public static boolean contains(int[]a,int v){for(int x:a)if(x==v)return true;return false;}}')
write('libcore/util/EmptyArray.java','package libcore.util;public class EmptyArray{public static final String[]STRING={};public static final int[]INT={};public static final long[]LONG={};}')
# Use the pinned actual arithmetic implementation called by VPN migration.
f=T/'packages/modules/Connectivity/staticlibs/framework/com/android/net/module/util/NetworkStatsUtils.java';inputs.append(f);text=f.read_text();start=text.index('public static long multiplySafeByRational(');opening=text.index('{',start);depth=1;end=opening+1
while depth:
 depth+=(text[end]=='{')-(text[end]=='}');end+=1
write('com/android/net/module/util/NetworkStatsUtils.java','package com.android.net.module.util;public class NetworkStatsUtils{'+text[start:end]+'}')
write('ConsumerTest.java',r'''
import com.android.server.*;import com.android.server.Gta3xlwifiStatsJournal.*;
import android.net.*;import java.util.*;import java.io.*;
public class ConsumerTest{
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("consumer case "+cases);++cases;}
 interface Action{void run()throws Exception;}static void rejected(Action x)throws Exception{try{x.run();throw new AssertionError("Expected IO failure "+cases);}catch(IOException expected){++cases;}}
 static class Remote extends PollTest.Remote{
  long[][]rows={{10001,123,0,17,2,100,1,50}};long nameLoss;boolean missing;Remote(List<String>e){super(e);}
  public long[]readStats(long session,int kind,int bank,long epoch)throws android.os.RemoteException{
   if(kind==4){validate(session);if(held)throw new android.os.ServiceSpecificException(11);return missing?new long[]{1,4,1,nameLoss,0}:new long[]{1,4,1,nameLoss,3,17,0x776c616eL,0x30000000L,0,0,18,0x76342d77L,0x6c616e30L,0,0,19,0x74756e30L,0,0,0};}
   if(kind==3){validate(session);return new long[]{1,3,1,0,1,17,2,100,1,50};}
   return super.readStats(session,kind,bank,epoch);
  }
  public long[]swapStats(long session,int bank,long epoch)throws android.os.RemoteException{
   long[]answer=super.swapStats(session,bank,epoch);long[]w=new long[7+rows.length*8];w[0]=1;w[1]=1;w[2]=answer[2];w[3]=answer[3];w[4]=answer[3];w[5]=nextLoss;w[6]=rows.length;for(int i=0;i<rows.length;++i)System.arraycopy(rows[i],0,w,7+8*i,8);frozen=w;return answer;
  }
 }
 static class Fixture{
  Object lock=new Object();List<String>events=new ArrayList<>();PollTest.Memory store=new PollTest.Memory(events);Remote remote=new Remote(events);Gta3xlwifiNetpolicyClient client;Gta3xlwifiStatsJournal journal;Gta3xlwifiStatsConsumer consumer;
  Fixture(boolean throttle,int threshold)throws Exception{client=Test.live(remote);journal=new Gta3xlwifiStatsJournal(lock,()->PollTest.BOOT,store);consumer=new Gta3xlwifiStatsConsumer(lock,client.statsAccess(),journal,throttle,threshold);}
  Fixture()throws Exception{this(false,1000);}NetworkStats poll()throws Exception{synchronized(lock){return consumer.readDetail(-1,null,-1);}}
  void recover()throws Exception{/* Explicit framework-death boundary: release old token, preserve kernel banks. */remote.client=null;remote.held=true;remote.active=false;client=Test.live(remote);consumer=new Gta3xlwifiStatsConsumer(lock,client.statsAccess(),journal,false,1000);}
 }
 static long bytes(NetworkStats stats,String iface,int uid,int set,int tag){int i=stats.findIndex(iface,uid,set,tag,0,0,0);return i<0?0:stats.getValues(i,null).rxBytes;}
 public static void main(String[]args)throws Exception{
  PollTest.main(args); // all61 old flows and1467 client checks execute first.
  {Fixture f=new Fixture();NetworkStats s=f.poll();check(s.size()==2&&bytes(s,"wlan0",10001,0,123)==100&&bytes(s,"wlan0",10001,0,0)==100);check(f.remote.acksCommitted==1&&f.store.writes==1);s.getValues(0,null).rxBytes=9;f.remote.rows=new long[0][];s=f.poll();check(bytes(s,"wlan0",10001,0,0)==100&&f.remote.acksCommitted==2);f.recover();check(bytes(f.poll(),"wlan0",10001,0,0)==100);}
  {Fixture f=new Fixture();f.remote.rows=new long[][]{{10001,0,0,17,2,100,0,0},{10001,123,0,17,1,50,0,0},{10001,123,1,17,1,75,0,0}};NetworkStats s=f.poll();check(s.size()==4&&bytes(s,"wlan0",10001,0,0)==150&&bytes(s,"wlan0",10001,1,0)==75);}
  {Fixture f=new Fixture(true,1);f.remote.rows=new long[][]{{10001,1,0,17,1,10,0,0},{10001,2,0,17,1,20,0,0}};NetworkStats s=f.poll();check(bytes(s,"wlan0",10001,0,1)==10&&bytes(s,"wlan0",10001,0,2)==0&&bytes(s,"wlan0",10001,0,0)==30);f.remote.rows=new long[][]{{10001,2,0,17,1,7,0,0}};s=f.poll();check(bytes(s,"wlan0",10001,0,2)==0&&bytes(s,"wlan0",10001,0,0)==37);}
  // Metadata is durable before the first receipt; actual464xlat adds20 bytes/packet.
  {Fixture f=new Fixture();synchronized(f.lock){f.consumer.noteStackedIface("v4-wlan0","wlan0");check(f.journal.loadCurrentBoot().receipt==null);f.consumer.updateUnderlyingNetworkInfos(new UnderlyingNetworkInfo[0]);}f.recover();f.remote.rows=new long[][]{{10001,0,0,18,2,100,0,0}};NetworkStats s=f.poll();check(bytes(s,"v4-wlan0",10001,0,0)==140);}
  // Run actual A17 VPN migration, and compare to its direct pipeline result.
  {Fixture f=new Fixture();UnderlyingNetworkInfo vpn=new UnderlyingNetworkInfo(10002,"tun0",List.of("wlan0"));synchronized(f.lock){f.consumer.updateUnderlyingNetworkInfos(new UnderlyingNetworkInfo[]{vpn});}f.remote.rows=new long[][]{{10001,0,0,19,2,100,0,0},{10002,0,0,17,2,100,0,0}};NetworkStats actual=f.poll();NetworkStats expected=new NetworkStats(1000,2);expected.combineValues(new NetworkStats.Entry("tun0",10001,0,0,0,0,0,100,2,0,0,0));expected.combineValues(new NetworkStats.Entry("wlan0",10002,0,0,0,0,0,100,2,0,0,0));expected.migrateTun(10002,"tun0",List.of("wlan0"));expected.filterDebugEntries();check(actual.size()==expected.size());for(int i=0;i<expected.size();++i){var e=expected.getValues(i,null);check(bytes(actual,e.iface,e.uid,e.set,e.tag)==e.rxBytes);}check(bytes(actual,"wlan0",10001,0,0)==100);}
  {Fixture f=new Fixture();f.poll();synchronized(f.lock){f.consumer.removeUids(new int[]{10001});}f.recover();f.remote.rows=new long[0][];check(f.poll().size()==0);}
  {Fixture f=new Fixture();f.remote.rows=new long[][]{{10001,0,0,18,2,Long.MAX_VALUE,0,0}};rejected(f::poll);check(f.remote.acksCommitted==0&&f.store.writes==0);}
  {Fixture f=new Fixture();synchronized(f.lock){f.consumer.updateUnderlyingNetworkInfos(new UnderlyingNetworkInfo[]{new UnderlyingNetworkInfo(10002,"tun0",List.of("wlan0"))});}f.remote.rows=new long[][]{{10001,0,0,19,1,Long.MAX_VALUE,0,0}};int writes=f.store.writes;rejected(f::poll);check(f.remote.acksCommitted==0&&f.store.writes==writes);}
  // Missing names/loss/unsigned overflow do not ACK or durably consume the bank.
  for(int fault=0;fault<4;++fault){Fixture f=new Fixture();if(fault==0)f.remote.missing=true;if(fault==1)f.remote.nameLoss=1;if(fault==2)f.remote.rows[0][5]=-1;if(fault==3)f.remote.nextLoss=1;rejected(f::poll);check(f.remote.acksCommitted==0&&f.store.writes==0&&f.remote.pending!=0);}
  {Fixture f=new Fixture();f.remote.rows=new long[][]{{10001,0,0,17,0,Long.MAX_VALUE,0,0},{10001,1,0,17,0,1,0,0}};rejected(f::poll);check(f.remote.acksCommitted==0&&f.store.writes==0);}
  // Durable write succeeded but reply failed: explicit reload resumes the exact receipt.
  {Fixture f=new Fixture();f.store.after=true;rejected(f::poll);check(f.remote.acksCommitted==0&&f.store.writes==1);f.recover();check(bytes(f.poll(),"wlan0",10001,0,0)==100&&f.store.writes==1&&f.remote.acksCommitted==1);}
  // Lost ACK reply also resumes without adding the frozen counters twice.
  {Fixture f=new Fixture();f.remote.fault="ack-before";rejected(f::poll);check(f.store.writes==1&&f.remote.pending!=0);f.remote.fault="";f.recover();check(bytes(f.poll(),"wlan0",10001,0,0)==100&&f.store.writes==1);}
  {Fixture f=new Fixture();synchronized(f.lock){NetworkStats s=f.consumer.readSummary();check(s.size()==1&&s.getValues(0,null).uid==-1&&s.getValues(0,null).set==-1&&s.getValues(0,null).rxBytes==100&&f.remote.swaps==0&&f.store.writes==0);}}
  // Truncation and trailing bytes must not publish partially decoded state.
  {Fixture f=new Fixture();f.poll();byte[]valid; synchronized(f.lock){valid=f.journal.loadCurrentBoot().payload();for(int n=0;n<valid.length;++n){byte[]bad=Arrays.copyOf(valid,n);rejected(()->f.consumer.restore(bad));}byte[]bad=Arrays.copyOf(valid,valid.length+1);rejected(()->f.consumer.restore(bad));}f.remote.rows=new long[0][];check(bytes(f.poll(),"wlan0",10001,0,0)==100);}
  {Fixture f=new Fixture();synchronized(f.lock){f.consumer.noteStackedIface("v4-wlan0","wlan0");byte[]before=f.store.bytes.clone();rejected(()->f.consumer.noteStackedIface("v4-wlan0","rmnet0"));check(Arrays.equals(before,f.store.bytes));rejected(()->f.consumer.noteStackedIface("bad/name","wlan0"));}}
  System.out.println("consumer_cases="+cases);
 }
}
''')

f=S/'java/com/android/server/net/NetworkStatsFactory.java';inputs.append(f)
assert sha(f)==r['inputs_sha256'][str(f)]
text=f.read_text();jni='    static {\n        System.loadLibrary("service-connectivity");\n    }'
# Remove only the Android JNI library-loading boundary; execute actual methods.
assert text.count(jni)==1
write('com/android/server/net/NetworkStatsFactory.java',text.replace(jni,'    // Explicit host JNI loading boundary fixture.'))
write('com/android/internal/annotations/GuardedBy.java','package com.android.internal.annotations;public @interface GuardedBy{String value();}')
write('android/content/Context.java','package android.content;public class Context{}')
write('android/provider/DeviceConfig.java','package android.provider;public class DeviceConfig{public static final String NAMESPACE_TETHERING="tethering";}')
write('android/os/SystemProperties.java','package android.os;public class SystemProperties{public static boolean getBoolean(String k,boolean d){throw new UnsupportedOperationException("Property boundary");}}')
write('android/util/ArraySet.java','package android.util;public class ArraySet<T>extends java.util.HashSet<T>{}')
write('android/util/Pair.java','package android.util;public class Pair<A,B>{public final A first;public final B second;public Pair(A a,B b){first=a;second=b;}}')
write('android/util/Log.java','package android.util;public class Log{public static int wtf(String t,String m){throw new AssertionError(m);}}')
write('android/util/SparseArray.java','package android.util;public class SparseArray<T>{java.util.TreeMap<Integer,T>m=new java.util.TreeMap<>();public T get(int k){return m.get(k);}public void put(int k,T v){m.put(k,v);}public int size(){return m.size();}public int keyAt(int i){return new java.util.ArrayList<>(m.keySet()).get(i);}public T valueAt(int i){return new java.util.ArrayList<>(m.values()).get(i);}}')
write('android/util/IndentingPrintWriter.java','package android.util;public class IndentingPrintWriter extends java.io.PrintWriter{public IndentingPrintWriter(java.io.Writer w){super(w);}public void increaseIndent(){}public void decreaseIndent(){}}')
write('com/android/net/module/util/DeviceConfigUtils.java','package com.android.net.module.util;import android.content.Context;public class DeviceConfigUtils{public static boolean isTetheringFeatureNotChickenedOut(Context c,String n){throw new UnsupportedOperationException("Config boundary");}public static int getDeviceConfigPropertyInt(String ns,String n,int d){throw new UnsupportedOperationException("Config boundary");}}')
write('com/android/server/connectivity/InterfaceTracker.java','package com.android.server.connectivity;public class InterfaceTracker{public InterfaceTracker(android.content.Context c){throw new UnsupportedOperationException("InterfaceTracker boundary");}}')
write('com/android/server/BpfNetMaps.java',"""package com.android.server;
public class BpfNetMaps{public int captures;final Gta3xlwifiStatsAccess access;
 public BpfNetMaps(android.content.Context c,com.android.server.connectivity.InterfaceTracker t){throw new UnsupportedOperationException("BpfNetMaps boundary");}
 public BpfNetMaps(Gta3xlwifiStatsAccess a){access=a;}
 public Gta3xlwifiStatsAccess gta3xlwifiStatsAccess(){captures++;return access;}
 public void swapActiveStatsMap(){throw new AssertionError("Private path attempted BPF swap");}}
""")
write('FactoryTest.java',r"""
import com.android.server.*;import com.android.server.net.*;import android.content.Context;import android.net.*;import java.io.*;import java.nio.file.*;import java.util.*;
public class FactoryTest{
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("factory case "+cases);++cases;}
 static class Deps extends NetworkStatsFactory.Dependencies{
  final BpfNetMaps maps;boolean legacy=true;int summaries;
  Deps(BpfNetMaps m){maps=m;}public boolean isLegacyNetworking(){return legacy;}
  public BpfNetMaps createBpfNetMaps(Context c){return maps;}
  public boolean isFeatureNotChickenedOut(Context c,String n){return false;}
  public int getDeviceConfigPropertyInt(String n,int d){return d;}
  public NetworkStats getNetworkStatsDetail(){throw new AssertionError("Private path attempted old JNI/proc counters");}
  public NetworkStats getNetworkStatsDev(){summaries++;return new NetworkStats(1000,0);}
 }
 public static void main(String[]args)throws Exception{
  ConsumerTest.main(args);
  Path root=Files.createTempDirectory("actual-factory-");android.system.Os.bootFile=root.resolve("boot-id");Files.writeString(android.system.Os.bootFile,PollTest.BOOT+"\n");
  ConsumerTest.Remote remote=new ConsumerTest.Remote(new ArrayList<>());Gta3xlwifiNetpolicyClient client=Test.live(remote);
  BpfNetMaps maps=new BpfNetMaps(client.statsAccess());Deps deps=new Deps(maps);NetworkStatsFactory factory=new NetworkStatsFactory(new Context(),deps);
  check(maps.captures==1);try{factory.readNetworkStatsDetail();throw new AssertionError();}catch(IOException expected){cases++;}
  Path dir=Files.createDirectory(root.resolve("netstats"));factory.initializePrivateStats(dir.toFile());factory.noteStackedIface("v4-wlan0","wlan0");factory.updateUnderlyingNetworkInfos(new UnderlyingNetworkInfo[0]);
  NetworkStats result=factory.readNetworkStatsDetail(10001,new String[]{"wlan0"},123);
  check(result.size()==1&&result.getValues(0,null).tag==123&&result.getValues(0,null).rxBytes==100&&remote.acksCommitted==1);
  check(Files.size(dir.resolve("gta3xlwifi-packet-state"))>100&&maps.captures==1&&deps.summaries==0);
  check(factory.readNetworkStatsSummaryXt().getValues(0,null).rxBytes==100&&deps.summaries==0&&maps.captures==1);
  StringWriter text=new StringWriter();factory.dump(new android.util.IndentingPrintWriter(text));check(text.toString().contains("durable revision=")&&text.toString().contains("rawRows=2"));
  remote.rows=new long[0][];factory.removeUidsLocked(new int[]{10001});check(factory.readNetworkStatsDetail().size()==0);
  // Execute the actual factory while another thread holds the real Java client lock.
  java.lang.reflect.Field field=Gta3xlwifiNetpolicyClient.class.getDeclaredField("mLock");field.setAccessible(true);Object clientLock=field.get(client);
  java.util.concurrent.FutureTask<NetworkStats> task=new java.util.concurrent.FutureTask<>(factory::readNetworkStatsDetail);
  synchronized(clientLock){Thread worker=new Thread(task);worker.start();check(task.get(3,java.util.concurrent.TimeUnit.SECONDS).size()==0);}
  check(maps.captures==1);
  // Same-boot new framework instance uses a new policy token but identical durable counters.
  remote.client=null;remote.held=true;remote.active=false;Gta3xlwifiNetpolicyClient next=Test.live(remote);NetworkStatsFactory replacement=new NetworkStatsFactory(new Context(),new Deps(new BpfNetMaps(next.statsAccess())));replacement.initializePrivateStats(dir.toFile());check(replacement.readNetworkStatsDetail().size()==0);
  try{replacement.initializePrivateStats(dir.toFile());throw new AssertionError();}catch(IllegalStateException expected){cases++;}
  Deps stock=new Deps(new BpfNetMaps(null));stock.legacy=false;NetworkStatsFactory ordinary=new NetworkStatsFactory(new Context(),stock);ordinary.initializePrivateStats(new File("/nonexistent"));check(ordinary.readNetworkStatsSummaryXt().size()==0&&stock.summaries==1&&stock.maps.captures==0);
  System.out.println("factory_cases="+cases);
 }
}
""")
f=S/'java/com/android/server/net/NetworkStatsService.java';inputs.append(f)
assert sha(f)==r['inputs_sha256'][str(f)]
service=f.read_text()
def method(signature):
 start=service.index(signature);opening=service.index('{',start);depth=1;end=opening+1
 while depth:
  depth+=(service[end]=='{')-(service[end]=='}');end+=1
 return service[start:end]
privacy=method('public StatsResult getUidStats(int uid)')
helper=method('private NetworkStats.Entry privateTrafficStats(')
convert=method('private StatsResult getStatsResultFromEntryOrNull(')
setter=method('private void setKernelCounterSet(int uid, int set)')
foreground=method('public void noteUidForeground(')
write('TrafficServiceMethods.java','''import android.annotation.Nullable;import com.android.server.*;import android.net.NetworkStats;import java.io.IOException;
class TrafficServiceMethods{
 static final String TAG="fixture";static final int SET_DEFAULT=0,SET_FOREGROUND=1;
 Gta3xlwifiStatsAccess mGtaStats;Gta3xlwifiTrafficStats mGtaTrafficStats;
 final Object mStatsLock=new Object(),mContext=new Object();final Cache mActiveUidCounterSet=new Cache();
 final Maps mUidCounterSetMap=new Maps();final Deps mDeps=new Deps();
 static class Binder{static int uid;static int getCallingUid(){return uid;}}
 static class StatsResult{long rxBytes,rxPackets,txBytes,txPackets;StatsResult(long rb,long rp,long tb,long tp){rxBytes=rb;rxPackets=rp;txBytes=tb;txPackets=tp;}}
 static class Log{static void w(String t,String m){}static void w(String t,String m,Exception e){}static void wtf(String t,String m){throw new AssertionError(m);}}
 static class ErrnoException extends Exception{}
 static class S32{S32(int x){}}static class U8{U8(short x){}}
 static class Maps{void deleteEntry(S32 k)throws ErrnoException{throw new AssertionError("Unexpected BPF mutation");}void updateEntry(S32 k,U8 v)throws ErrnoException{throw new AssertionError("Unexpected BPF mutation");}}
 static class Cache{java.util.Map<Integer,Integer>m=new java.util.HashMap<>();int get(int uid,int value){return m.getOrDefault(uid,value);}void put(int uid,int set){m.put(uid,set);}}
 static class Deps{NetworkStats.Entry nativeGetUidStat(int uid){throw new AssertionError("Unexpected old JNI read");}}
 static class PermissionUtils{static void enforceNetworkStackPermission(Object c){if(Binder.uid!=1000)throw new SecurityException();}}
'''+privacy+'\n'+helper+'\n'+convert+'\n'+setter+'\n'+foreground+'\n}')
write('TrafficTest.java',r"""
import com.android.server.*;import android.net.*;import java.util.*;import java.io.*;
public class TrafficTest{
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("traffic case "+cases);++cases;}
 interface Action{void run()throws Exception;}static void rejected(Action x)throws Exception{try{x.run();throw new AssertionError("Missing failure");}catch(IOException expected){cases++;}}
 static class Remote extends ConsumerTest.Remote{
  long appLoss,ifaceLoss;boolean unknown;int namesRead;boolean failCounter;int counterWrites,uid,set;
  long[][]appRows={{10001,2,100,1,50},{10002,3,200,2,60}};long[][]ifaceRows={{17,2,100,1,50},{18,3,200,2,60}};
  Remote(){super(new ArrayList<>());}
  long[]table(int kind,long loss,long[][]rows){long[]out=new long[5+5*rows.length];out[0]=1;out[1]=kind;out[2]=7;out[3]=loss;out[4]=rows.length;for(int i=0;i<rows.length;i++)System.arraycopy(rows[i],0,out,5+i*5,5);return out;}
  public long[]readStats(long session,int kind,int bank,long epoch)throws android.os.RemoteException{validate(session);if(held)throw new android.os.ServiceSpecificException(11);if(kind==2)return table(2,appLoss,appRows);if(kind==3)return table(3,ifaceLoss,ifaceRows);if(kind==4){namesRead++;if(unknown)return new long[]{1,4,1,0,0};}return super.readStats(session,kind,bank,epoch);}
  public void setStatsCounterset(long session,int uid,int set)throws android.os.RemoteException{validate(session);counterWrites++;if(failCounter)throw new android.os.RemoteException("counterset uncertain");this.uid=uid;this.set=set;}
 }
 public static void main(String[]args)throws Exception{
  FactoryTest.main(args);
  Remote remote=new Remote();Gta3xlwifiNetpolicyClient client=Test.live(remote);Gta3xlwifiTrafficStats stats=new Gta3xlwifiTrafficStats(client.statsAccess());
  var uid=stats.uid(10001);check(uid.rxBytes==100&&uid.rxPackets==2&&uid.txBytes==50&&uid.txPackets==1);check(stats.uid(33333).rxBytes==0);check(remote.swaps==0&&remote.acks==0&&remote.namesRead==0);
  check(stats.iface(null).rxBytes==300&&remote.namesRead==0);check(stats.iface("wlan0").rxBytes==100&&stats.iface("v4-wlan0").rxBytes==200);check(stats.iface("absent0").rxBytes==0);uid.rxBytes=99;check(stats.uid(10001).rxBytes==100);
  remote.appLoss=1;rejected(()->stats.uid(10001));remote.appLoss=0;remote.ifaceLoss=1;rejected(()->stats.iface(null));remote.ifaceLoss=0;
  remote.unknown=true;rejected(()->stats.iface("wlan0"));check(stats.iface(null).rxBytes==300);remote.unknown=false;
  remote.ifaceRows[0][2]=Long.MAX_VALUE;rejected(()->stats.iface(null));remote.ifaceRows[0][2]=100;
  remote.appRows[0][2]=-1;rejected(()->stats.uid(10001));remote.appRows[0][2]=100;rejected(()->stats.uid(-1));
  TrafficServiceMethods service=new TrafficServiceMethods();service.mGtaStats=client.statsAccess();service.mGtaTrafficStats=stats;
  for(int calling:new int[]{0,10000,101000,101001}){TrafficServiceMethods.Binder.uid=calling;check(service.getUidStats(10001)==null);}
  TrafficServiceMethods.Binder.uid=10001;check(service.getUidStats(10001).rxBytes==100&&service.getUidStats(10002)==null);
  TrafficServiceMethods.Binder.uid=1000;check(service.getUidStats(10002).rxBytes==200);
  remote.held=true;check(service.getUidStats(10001)==null);remote.held=false;check(!client.needsCompleteResnapshot());
  service.noteUidForeground(10001,true);check(remote.counterWrites==1&&remote.uid==10001&&remote.set==1&&service.mActiveUidCounterSet.get(10001,0)==1);
  service.noteUidForeground(10001,true);check(remote.counterWrites==1);
  service.noteUidForeground(10001,false);check(remote.counterWrites==2&&remote.set==0&&service.mActiveUidCounterSet.get(10001,1)==0);
  remote.failCounter=true;try{service.noteUidForeground(10001,true);throw new AssertionError();}catch(IllegalStateException expected){check(service.mActiveUidCounterSet.get(10001,1)==0&&remote.counterWrites==3&&client.needsCompleteResnapshot());}
  System.out.println("traffic_cases="+cases);
 }
}
""")


# Explicit no-implementation default preserves prior boundary fixtures; only the
# new cleanup fixture below implements this operation. Production stubs are AIDL.
f=O/'com/android/internal/net/IGta3xlwifiNetpolicy.java';text=f.read_text();pos=text.rindex('}')
text=text[:pos]+"default void removeUidAccounting(long session,int uid,long generation,long epoch)throws android.os.RemoteException{throw new UnsupportedOperationException();}\n"+text[pos:];f.write_text(text)
write('UidCleanupTest.java',r'''
import com.android.server.*;import java.io.*;
public class UidCleanupTest{
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("cleanup case "+cases);++cases;}
 static class Remote extends TrafficTest.Remote{
  int removals;int removedUid;long generation,epoch;boolean fail;
  public void removeUidAccounting(long session,int uid,long gen,long ep)throws android.os.RemoteException{
   validate(session);removals++;removedUid=uid;generation=gen;epoch=ep;if(fail)throw new android.os.RemoteException("uncertain deletion");
  }
 }
 public static void main(String[]args)throws Exception{
  TrafficTest.main(args);Remote remote=new Remote();Gta3xlwifiNetpolicyClient client=Test.live(remote);Gta3xlwifiStatsAccess access=client.statsAccess();
  access.removeUidAccounting(10001,0,1);check(remote.removals==1&&remote.removedUid==10001&&remote.generation==0&&remote.epoch==1&&!client.needsCompleteResnapshot());
  access.removeUidAccounting(123,77,Long.MIN_VALUE);check(remote.removals==2&&remote.removedUid==123&&remote.generation==77&&remote.epoch==Long.MIN_VALUE);
  for(int fault=0;fault<3;++fault){try{access.removeUidAccounting(fault==0?-1:123,fault==1?-1:0,fault==2?0:1);throw new AssertionError();}catch(IllegalArgumentException expected){check(remote.removals==2);}}
  remote.fail=true;try{access.removeUidAccounting(123,0,1);throw new AssertionError();}catch(IOException expected){check(remote.removals==3&&client.needsCompleteResnapshot()&&remote.held&&remote.client==null);}
  check(remote.removals==3);System.out.println("uid_cleanup_java_cases="+cases);
 }
}
''')

f=O/'com/android/internal/net/IGta3xlwifiNetpolicy.java';text=f.read_text();pos=text.rindex('}')
text=text[:pos]+"default void removeUidAccountingOnce(long session,int uid,long generation,long epoch,long nonce)throws android.os.RemoteException{throw new UnsupportedOperationException();}\n"+text[pos:];f.write_text(text)
write('UidReceiptTest.java',r'''
import com.android.server.*;import java.io.*;
public class UidReceiptTest{
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("receipt case "+cases);++cases;}
 static class Remote extends UidCleanupTest.Remote{
  long[]receipt={1,5,0,0,0,0,0};int onceCalls;boolean onceFault;
  public long[]readStats(long session,int kind,int bank,long epoch)throws android.os.RemoteException{
   if(kind==5){validate(session);return receipt.clone();}return super.readStats(session,kind,bank,epoch);
  }
  public void removeUidAccountingOnce(long session,int uid,long gen,long ep,long nonce)throws android.os.RemoteException{
   validate(session);onceCalls++;receipt=new long[]{1,5,2,uid,nonce,gen,ep};if(onceFault)throw new android.os.RemoteException("uncertain receipt completion");
  }
 }
 interface Action{void run()throws Exception;}static void badIo(Action x)throws Exception{try{x.run();throw new AssertionError();}catch(IOException expected){cases++;}}
 public static void main(String[]args)throws Exception{
  UidCleanupTest.main(args);Remote r=new Remote();Gta3xlwifiNetpolicyClient client=Test.live(r);Gta3xlwifiStatsAccess a=client.statsAccess();var receipt=a.readUidCleanup();check(receipt.phase==0&&receipt.nonce==0&&receipt.uid==0&&!client.needsCompleteResnapshot());
  a.removeUidAccountingOnce(123,0,Long.MIN_VALUE,Long.MIN_VALUE);receipt=a.readUidCleanup();check(receipt.phase==2&&receipt.uid==123&&receipt.generation==0&&receipt.activeEpoch==Long.MIN_VALUE&&receipt.nonce==Long.MIN_VALUE&&r.onceCalls==1);
  for(int field=0;field<4;++field){try{a.removeUidAccountingOnce(field==0?-1:123,field==1?-1:0,field==2?0:1,field==3?0:1);throw new AssertionError();}catch(IllegalArgumentException expected){check(r.onceCalls==1);}}
  for(int fault=0;fault<10;++fault){Remote broken=new Remote();var c=Test.live(broken);var access=c.statsAccess();broken.receipt=new long[]{1,5,2,123,7,1,2};switch(fault){case 0:broken.receipt[0]=2;break;case 1:broken.receipt[1]=6;break;case 2:broken.receipt[2]=3;break;case 3:broken.receipt[3]=-1;break;case 4:broken.receipt[3]=0x80000000L;break;case 5:broken.receipt[4]=0;break;case 6:broken.receipt[5]=-1;break;case 7:broken.receipt[6]=0;break;case 8:broken.receipt=new long[]{1,5,0,1,0,0,0};break;case 9:broken.receipt=new long[]{1,5,0,0,0,0};break;}badIo(access::readUidCleanup);check(c.needsCompleteResnapshot()&&broken.held&&broken.client==null&&broken.onceCalls==0);}
  Remote broken=new Remote();var c=Test.live(broken);var access=c.statsAccess();broken.onceFault=true;badIo(()->access.removeUidAccountingOnce(123,1,2,7));check(broken.onceCalls==1&&c.needsCompleteResnapshot()&&broken.receipt[2]==2);check(broken.onceCalls==1);
  System.out.println("uid_receipt_java_cases="+cases);
 }
}
''')

f=O/'com/android/internal/net/IGta3xlwifiNetpolicy.java';text=f.read_text();pos=text.rindex('}')
text=text[:pos]+"default void abortSession(long session,android.os.IBinder token)throws android.os.RemoteException{throw new UnsupportedOperationException(\"Explicit old fixture has no terminal abort\");}\n"+text[pos:];f.write_text(text)
f=O/'android/system/OsConstants.java';text=f.read_text().replace('public class OsConstants{','public class OsConstants{public static final int EBUSY=16;');assert 'EBUSY' in text;f.write_text(text)
write('TerminalAbortTest.java',r'''
import com.android.server.*;import android.os.*;import java.io.*;
public class TerminalAbortTest{
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("abort case "+cases);++cases;}
 static class Remote extends UidReceiptTest.Remote{
  int aborts,seenSession;IBinder seenToken;boolean rejectOnce,stale,failRead;
  public void abortSession(long session,IBinder token)throws android.os.RemoteException{
   validate(session);if(token!=client)throw new ServiceSpecificException(116);aborts++;seenSession=(int)session;seenToken=token;held=true;client=null;
  }
  public long readGeneration(long session)throws android.os.RemoteException{if(stale)throw new ServiceSpecificException(116);return super.readGeneration(session);}
  public void removeUidAccountingOnce(long session,int uid,long gen,long ep,long nonce)throws android.os.RemoteException{
   validate(session);if(rejectOnce)throw new ServiceSpecificException(116);super.removeUidAccountingOnce(session,uid,gen,ep,nonce);
  }
  public long[]readStats(long session,int kind,int bank,long epoch)throws android.os.RemoteException{if(failRead)throw new android.os.RemoteException("read unavailable");return super.readStats(session,kind,bank,epoch);}
 }
 interface Action{void run()throws Exception;}static void badIo(Action x)throws Exception{try{x.run();throw new AssertionError();}catch(IOException expected){cases++;}}
 public static void main(String[]args)throws Exception{
  UidReceiptTest.main(args);
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();r.failRead=true;badIo(a::readState);check(r.aborts==1&&r.seenSession>0&&r.seenToken!=null&&r.held&&c.needsCompleteResnapshot());int seen=r.statReads;badIo(a::readState);badIo(()->a.removeUidAccountingOnce(123,1,2,3));check(r.aborts==1&&r.statReads==seen);}
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();r.rejectOnce=true;try{a.removeUidAccountingOnce(123,0,1,1);throw new AssertionError();}catch(Gta3xlwifiStatsAccess.UidCleanupRejectedException e){check(e.errorCode==116&&e.currentGeneration==r.readGeneration(r.session)&&r.aborts==0&&!c.needsCompleteResnapshot()&&!r.held&&r.onceCalls==0);}}
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();r.rejectOnce=true;r.stale=true;badIo(()->a.removeUidAccountingOnce(123,0,1,1));check(r.aborts==1&&c.needsCompleteResnapshot());}
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();check(a.generation()==r.readGeneration(r.session));c.close();check(r.aborts==0&&r.held);}
  {Remote r=new Remote();var c=Test.live(r);c.abortCurrentSession();check(r.aborts==1&&r.held&&c.needsCompleteResnapshot());}
  {Remote r=new Remote();var c=Test.live(r);r.fault="commit-after";try{c.publishCompleteSnapshot(Test.frame());throw new AssertionError();}catch(android.os.RemoteException expected){check(r.aborts==1&&r.held&&c.needsCompleteResnapshot());}}
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();IBinder token=r.client;r.session++;badIo(a::readState);check(r.aborts==0&&r.closes==0&&r.client==token&&!r.held&&c.needsCompleteResnapshot());}
  {Remote r=new Remote();var c=Test.live(r);IBinder token=r.client;r.session++;try{c.abortCurrentSession();throw new AssertionError();}catch(ServiceSpecificException expected){check(expected.errorCode==116&&r.closes==0&&r.client==token&&!r.held&&c.needsCompleteResnapshot());}}
  System.out.println("terminal_abort_java_cases="+cases);
 }
}
''')
sources=[S/'java/com/android/server'/n for n in ['Gta3xlwifiNetpolicyClient.java','Gta3xlwifiStatsAccess.java','Gta3xlwifiStatsJournal.java','Gta3xlwifiStatsPoller.java','Gta3xlwifiStatsConsumer.java','Gta3xlwifiTrafficStats.java']]
for f in sources:assert sha(f)==r['inputs_sha256'][str(f)]
javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';cmd=[str(javac),'-source','21','-target','21','-d',str(O/'classes'),*map(str,sources),*map(str,O.rglob('*.java'))]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(javac.with_name('java')),'-ea','-cp',str(O/'classes'),'TerminalAbortTest'],capture_output=True,text=True,timeout=90);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'terminal_abort_java_cases=(\d+)\n$',x.stdout);assert m
inputs += [*sources,*O.rglob('*.java')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'terminal_abort_java_cases':int(m[1]),'uid_receipt_java_cases':int(re.search(r'uid_receipt_java_cases=(\d+)',x.stdout)[1]),'uid_cleanup_java_cases':int(re.search(r'uid_cleanup_java_cases=(\d+)',x.stdout)[1]),'traffic_cases':int(re.search(r'traffic_cases=(\d+)',x.stdout)[1]),'factory_cases':int(re.search(r'factory_cases=(\d+)',x.stdout)[1]),'consumer_cases':int(re.search(r'consumer_cases=(\d+)',x.stdout)[1]),'actual_factory_methods_with_JNI_loading_boundary_fixture':True,'prior_61_poll_and_1467_client_cases_replayed':True,'actual_A17_NetworkStats_and_UnderlyingNetworkInfo_unmodified':True,'actual_pinned_VPN_arithmetic':True,'source_hashes':{str(f):sha(f) for f in inputs},'command':cmd,'actual_NetworkStatsFactory_routing':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
