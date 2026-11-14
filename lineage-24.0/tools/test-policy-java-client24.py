#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute actual Java complete-policy client with explicit Binder/daemon fixtures.

Interface declarations come verbatim from actual Android-generated AIDL. This
exercises Java lifecycle/serialization, not real Binder, native packets or Ready.
"""
import argparse,fcntl,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();native=json.loads(a.native_report.read_text());assert native['passed'] and native['framework_transport_client_compiled']
source=S/'java/com/android/server/Gta3xlwifiNetpolicyClient.java';assert sha(source)==native['inputs_sha256'][str(source)]
def put(path,text):p=O/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
put('android/os/RemoteException.java','package android.os; public class RemoteException extends Exception { public RemoteException(String s){super(s);} }')
put('android/os/ServiceSpecificException.java','package android.os; public class ServiceSpecificException extends RuntimeException { public final int errorCode; public ServiceSpecificException(int e){errorCode=e;} }')
put('android/os/IInterface.java','package android.os; public interface IInterface { IBinder asBinder(); }')
put('android/os/IBinder.java','package android.os; public interface IBinder { interface DeathRecipient { void binderDied(); } void linkToDeath(DeathRecipient d,int flags) throws RemoteException; boolean unlinkToDeath(DeathRecipient d,int flags); }')
put('android/os/Binder.java','''package android.os; import java.util.*; public class Binder implements IBinder { private final List<DeathRecipient> deaths=new ArrayList<>(); public int links,unlinks; public void linkToDeath(DeathRecipient d,int flags){deaths.add(d);links++;} public boolean unlinkToDeath(DeathRecipient d,int flags){unlinks++;return deaths.remove(d);} public void kill(){var old=List.copyOf(deaths);deaths.clear();for(var d:old)d.binderDied();} }''')
put('android/system/OsConstants.java','package android.system; public class OsConstants { public static final int ESTALE=116; }')
put('android/net/INetd.java','package android.net; public interface INetd { android.os.IBinder getOemNetd() throws android.os.RemoteException; }')
generated=a.native_report.parent/'java/com/android/internal/net/IGta3xlwifiNetpolicy.java'
methods=re.findall(r'^  public (?:long|void) \w+\([^\n]+\) throws android.os.RemoteException;',generated.read_text(),re.M);assert len(methods)==7
put('com/android/internal/net/IGta3xlwifiNetpolicy.java','package com.android.internal.net; public interface IGta3xlwifiNetpolicy extends android.os.IInterface {\n'+'\n'.join(methods)+'\n}')
put('com/android/internal/net/IOemNetd.java','''package com.android.internal.net; public interface IOemNetd { IGta3xlwifiNetpolicy getGta3xlwifiNetpolicy() throws android.os.RemoteException; class Stub { public static IOemNetd asInterface(android.os.IBinder b){return (IOemNetd)b;} } }''')
put('Test.java',r'''
import android.os.*;
import com.android.internal.net.*;
import com.android.server.Gta3xlwifiNetpolicyClient;
import com.android.server.Gta3xlwifiNetpolicyClient.Frame;
import java.util.*;
import java.util.concurrent.*;
public class Test {
 static int cases;
 static void check(boolean x){if(!x)throw new AssertionError("case "+cases);cases++;}
 interface Action { void run() throws Exception; }
 static void rejected(Class<?> type,Action action) throws Exception {try{action.run();throw new AssertionError("missing "+type);}catch(Exception e){check(type.isInstance(e));}}
 static int[][] sections(){int[][] s=new int[10][];Arrays.setAll(s,i->new int[0]);s[0]=new int[]{0};s[1]=new int[]{10001,10002};s[2]=new int[]{0,1023,1000,1023,10001,4};s[3]=new int[24];for(int i=0;i<12;i++)s[3][2*i]=i+1;return s;}
 static Frame frame(){return new Frame(sections(),7,true,true,false);}
 static class Remote extends Binder implements IGta3xlwifiNetpolicy {
  IBinder client;long serial,session,generation;boolean held=true,active;int[][] image;int[] offsets;int opens,created,commits,chunks,maxChunk,closes,reads;String fault="";Map<String,Integer> calls=new HashMap<>();boolean faultTaken;
  void point(String name) throws RemoteException {calls.merge(name,1,Integer::sum);if(name.equals(fault)&&!faultTaken){faultTaken=true;throw new RemoteException(name);}}
  void validate(long s){if(client==null||s!=session)throw new ServiceSpecificException(116);}
  public IBinder asBinder(){return this;}
  public long openSession(IBinder token,int version)throws RemoteException {opens++;check(version==1);if(client!=null){check(client==token);return session;}client=token;session=++serial;created++;point("open-after");return session;}
  public long readGeneration(long s)throws RemoteException {validate(s);reads++;point("read");return held?0:generation;}
  public void beginFrame(long s,long previous,int[] counts,int flags,boolean loop,boolean migration,boolean saver)throws RemoteException {validate(s);point("begin");check(!active&&previous==(held?0:generation));check(flags==7&&loop&&migration&&!saver);check(counts.length==10);image=new int[10][];for(int i=0;i<10;i++)image[i]=new int[counts[i]];offsets=new int[10];active=true;}
  public void appendFrame(long s,int section,int offset,int[] words)throws RemoteException {validate(s);point("append");check(active&&words.length>0&&words.length<=4096);check(offset==offsets[section]);System.arraycopy(words,0,image[section],offset,words.length);offsets[section]+=words.length;chunks++;maxChunk=Math.max(maxChunk,words.length);}
  public long commitFrame(long s)throws RemoteException {validate(s);point("commit-before");check(active);for(int i=0;i<10;i++)check(offsets[i]==image[i].length);active=false;held=false;generation++;commits++;point("commit-after");return generation;}
  public void abandonFrame(long s)throws RemoteException {validate(s);point("abandon");active=false;}
  public void closeSession(IBinder token)throws RemoteException {closes++;point("close-before");if(client==null||client!=token)throw new ServiceSpecificException(116);held=true;active=false;client=null;point("close-after");}
 }
 static class Oem extends Binder implements IOemNetd {Remote remote;int gets;Oem(Remote r){remote=r;}public IGta3xlwifiNetpolicy getGta3xlwifiNetpolicy(){gets++;return remote;}}
 public static void main(String[]args)throws Exception{
  Remote remote=new Remote();Oem oem=new Oem(remote);var client=Gta3xlwifiNetpolicyClient.lookup(()->oem);check(oem.gets==1&&remote.opens==0&&client.needsCompleteResnapshot());client.start();check(remote.opens==1&&client.needsCompleteResnapshot());client.start();check(remote.opens==1);
  int[][] original=sections();Frame immutable=new Frame(original,7,true,true,false);original[0][0]=123;original[1][0]=777;original[2]=null;check(client.publishCompleteSnapshot(immutable)==1&&!client.needsCompleteResnapshot());check(remote.image[0][0]==0&&remote.image[1][0]==10001&&remote.image[2][5]==4);check(remote.links==1);
  int[][] large=sections();large[1]=new int[65536];for(int i=0;i<large[1].length;i++)large[1][i]=i;check(client.publishCompleteSnapshot(new Frame(large,7,true,true,false))==2);check(remote.maxChunk==4096&&Arrays.equals(remote.image[1],large[1]));check(remote.image[9].length==0);
  // Calls on one client cannot interleave frames even across framework threads.
  ExecutorService pool=Executors.newFixedThreadPool(2);CountDownLatch go=new CountDownLatch(1);Future<Long>first=pool.submit(()->{go.await();return client.publishCompleteSnapshot(frame());});Future<Long>second=pool.submit(()->{go.await();return client.publishCompleteSnapshot(frame());});go.countDown();Set<Long>results=Set.of(first.get(),second.get());check(results.equals(Set.of(3L,4L)));pool.shutdown();
  client.close();check(remote.held&&remote.client==null&&remote.unlinks==1);client.close();check(remote.closes==1);rejected(IllegalStateException.class,client::start);rejected(IllegalStateException.class,()->client.publishCompleteSnapshot(frame()));
  // Lost OPEN reply can be recovered with an explicit same-token start, never duplicate ownership.
  {Remote r=new Remote();r.fault="open-after";var c=new Gta3xlwifiNetpolicyClient(r);rejected(RemoteException.class,c::start);check(c.needsCompleteResnapshot()&&r.created==1);c.start();check(r.opens==2&&r.created==1);check(c.publishCompleteSnapshot(frame())==1);c.close();}
  // Explicit token close also cleans up an interrupted OPEN with unknown session.
  {Remote r=new Remote();r.fault="open-after";var c=new Gta3xlwifiNetpolicyClient(r);rejected(RemoteException.class,c::start);c.close();check(r.held&&r.client==null&&r.unlinks==1);}
  for(String fault:List.of("read","abandon","begin","append","commit-before","commit-after")){
   Remote r=new Remote();var c=new Gta3xlwifiNetpolicyClient(r);c.start();check(c.publishCompleteSnapshot(frame())==1);r.calls.clear();r.fault=fault;
   rejected(RemoteException.class,()->c.publishCompleteSnapshot(frame()));check(c.needsCompleteResnapshot()&&r.held&&r.client==null);check(r.calls.get(fault)==1&&r.closes==1);rejected(IllegalStateException.class,()->c.publishCompleteSnapshot(frame()));
   // New session requires a fresh explicit complete frame and retains native generation monotonicity.
   var next=new Gta3xlwifiNetpolicyClient(r);next.start();long before=r.generation;check(next.needsCompleteResnapshot());check(next.publishCompleteSnapshot(frame())==before+1);next.close();
  }
  // A failed retirement is retained for explicit retry; no subsequent policy may use that client.
  {Remote r=new Remote();var c=new Gta3xlwifiNetpolicyClient(r);c.start();c.publishCompleteSnapshot(frame());r.fault="close-before";rejected(RemoteException.class,c::close);check(r.client!=null&&r.unlinks==0);rejected(IllegalStateException.class,()->c.publishCompleteSnapshot(frame()));c.close();check(r.held&&r.client==null&&r.unlinks==1&&r.closes==2);}
  // Lost successful CLOSE reply returns ESTALE on explicit retry, safely retiring only the old token.
  {Remote r=new Remote();var c=new Gta3xlwifiNetpolicyClient(r);c.start();r.fault="close-after";rejected(RemoteException.class,c::close);check(r.held&&r.client==null&&r.unlinks==0);c.close();check(r.closes==2&&r.unlinks==1);}
  {Remote r=new Remote();var c=new Gta3xlwifiNetpolicyClient(r);c.start();r.kill();check(c.needsCompleteResnapshot());rejected(IllegalStateException.class,c::start);rejected(IllegalStateException.class,()->c.publishCompleteSnapshot(frame()));c.close();check(r.closes==0);}
  rejected(NullPointerException.class,()->new Frame(null,7,true,true,false));rejected(IllegalArgumentException.class,()->new Frame(new int[9][],7,true,true,false));rejected(IllegalArgumentException.class,()->new Frame(sections(),8,true,true,false));rejected(IllegalArgumentException.class,()->new Frame(sections(),7,true,false,false));
  for(int section=0;section<10;section++){int[][] s=sections();s[section]=null;rejected(NullPointerException.class,()->new Frame(s,7,true,true,false));}
  int[] limits={65536,65536,131072,24,480000,80000,600,8000,8000,1000};for(int section=0;section<10;section++){int[][]s=sections();s[section]=new int[limits[section]+1];rejected(IllegalArgumentException.class,()->new Frame(s,7,true,true,false));}
  {int[][]s=sections();s[3]=new int[22];rejected(IllegalArgumentException.class,()->new Frame(s,7,true,true,false));}
  System.out.println("passed_cases="+cases);
 }
}
''')
javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';java=javac.with_name('java');classes=O/'classes';classes.mkdir();command=[str(javac),'-source','21','-target','21','-d',str(classes),str(source),*map(str,O.rglob('*.java'))]
x=subprocess.run(command,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(java),'-ea','-cp',str(classes),'Test'],capture_output=True,text=True,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m
inputs=[Path(__file__),source,a.native_report,generated,*O.rglob('*.java')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'actual_generated_interface_declarations':7,'chunk_words_bound':4096,'large_snapshot_known_UIDs':65536,'lost_open_close_and_commit_replies_tested':True,'publication_failures_retire_and_hold':True,'concurrent_frames_serialized':True,'inputs_sha256':{str(p):sha(p) for p in inputs},'command':command,'real_Binder_tested':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
