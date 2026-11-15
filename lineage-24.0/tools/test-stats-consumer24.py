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
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads(a.native_report.read_text());old=json.loads((R/'report.json').read_text());assert r['passed'] and r['actual_complete_consumer_compiled'] and old['passed'] and old['poll_cases']==61
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
sources=list((S/'java').rglob('*.java'))
for f in sources:assert sha(f)==r['inputs_sha256'][str(f)]
javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';cmd=[str(javac),'-source','21','-target','21','-d',str(O/'classes'),*map(str,sources),*map(str,O.rglob('*.java'))]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(javac.with_name('java')),'-ea','-cp',str(O/'classes'),'ConsumerTest'],capture_output=True,text=True,timeout=90);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'consumer_cases=(\d+)\n$',x.stdout);assert m
inputs += [*sources,*O.rglob('*.java')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'consumer_cases':int(m[1]),'prior_61_poll_and_1467_client_cases_replayed':True,'actual_A17_NetworkStats_and_UnderlyingNetworkInfo_unmodified':True,'actual_pinned_VPN_arithmetic':True,'source_hashes':{str(f):sha(f) for f in inputs},'command':cmd,'actual_NetworkStatsFactory_routing':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
