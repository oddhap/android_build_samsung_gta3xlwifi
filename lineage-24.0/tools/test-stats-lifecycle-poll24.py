#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual stats client/journal/poller flow with explicit Binder/kernel/store consumers.

Replays1467 Java policy/stats checks. The consumer is an explicit fixture, not
NetworkStatsFactory serialization or actual Android IPC/hardware execution.
"""
import argparse,fcntl,hashlib,json,shutil,subprocess,re
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','client-reference','journal-reference','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();C=a.client_reference.resolve();J=a.journal_reference.resolve();assert not O.exists();lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads(a.native_report.read_text());assert r['passed'] and r['actual_lifecycle_journal_and_poller_compiled'];c=json.loads((C/'report.json').read_text());j=json.loads((J/'report.json').read_text());assert c['passed'] and c['passed_cases']==1467 and j['passed'] and j['journal_schema_version']==2
for root,report in [(C,c),(J,j)]:
 for name,h in report['inputs_sha256'].items():assert sha(Path(name))==h
for root in [C,J]:
 for f in root.rglob('*.java'):
  rel=f.relative_to(root)
  if rel==Path('Test.java') and root==J:continue
  q=O/rel;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,q)
p=O/'android/system/OsConstants.java';text=p.read_text().replace('public static final int O_RDONLY=', 'public static final int ESTALE=116,EAGAIN=11;public static final int O_RDONLY=');p.write_text(text)
p=O/'Test.java';p.write_text(p.read_text().replace('public static void main(String[]args)', 'public static void previousClientTests(String[]args)'))
(O/'PollTest.java').write_text(r'''
import com.android.server.*;
import com.android.server.Gta3xlwifiStatsJournal.*;
import java.io.*;import java.nio.*;import java.util.*;
public class PollTest{
 static int cases;static void check(boolean value){if(!value)throw new AssertionError("poll case "+cases);++cases;}
 interface Action{void run()throws Exception;}
 static void rejected(Action a)throws Exception{try{a.run();throw new AssertionError("missing IO failure");}catch(IOException expected){++cases;}}
 static final String BOOT="00112233-4455-4677-8899-aabbccddeeff";
 static class Memory implements Store{byte[]bytes;int writes;boolean before,after,readFault;List<String>events;Memory(List<String>e){events=e;}public byte[]read()throws IOException{if(readFault)throw new IOException("read");return bytes==null?null:bytes.clone();}public void writeDurably(byte[]value)throws IOException{writes++;events.add("write");if(before){before=false;throw new IOException("before");}bytes=value.clone();if(after){after=false;throw new IOException("after");}}}
 static class Consumer implements Gta3xlwifiStatsPoller.Consumer{long total;int prepares,restores,failRestoreAt;boolean failPrepare;List<String>events;Consumer(List<String>e){events=e;}public void restore(byte[]value)throws IOException{restores++;if(restores==failRestoreAt)throw new IOException("install");if(value!=null&&value.length!=8)throw new IOException("consumer state");long next=value==null?0:ByteBuffer.wrap(value).getLong();total=next;events.add("restore="+total);}public byte[]prepare(Gta3xlwifiStatsAccess.Snapshot frozen)throws IOException{prepares++;events.add("prepare");if(failPrepare){failPrepare=false;throw new IOException("prepare");}long sum=total;for(int i=0;i<frozen.count;i++){long bytes=frozen.row(i)[5];if(bytes<0)throw new IOException("unsigned counter overflow");try{sum=Math.addExact(sum,bytes);}catch(ArithmeticException e){throw new IOException(e);}}return ByteBuffer.allocate(8).putLong(sum).array();}}
 static class Remote extends Test.StatsRemote{
  int activeBank,pending,swapsCommitted,acksCommitted;long epoch=1,nextDelta=10,nextLoss;long[]epochs={1,0},frozen;List<String>events;Remote(List<String>e){events=e;}
  public long[]readStats(long session,int kind,int bank,long expected)throws android.os.RemoteException{validate(session);if(held)throw new android.os.ServiceSpecificException(11);if(kind==0)return new long[]{1,0,activeBank,epoch,pending,(pending&1)!=0?1:0,(pending&2)!=0?1:0,epochs[0],epochs[1],0,0,0,0,0,0};if(kind!=1||frozen==null||bank!=(int)frozen[2]||expected!=frozen[3]||(pending&(1<<bank))==0)throw new android.os.ServiceSpecificException(61);return frozen.clone();}
  public long[]swapStats(long session,int bank,long expected)throws android.os.RemoteException{validate(session);swaps++;events.add("swap-attempt");point("swap-before");if(pending!=0||bank!=activeBank||expected!=epoch)throw new android.os.ServiceSpecificException(116);int old=activeBank;long oldEpoch=epoch;pending=1<<old;frozen=nextDelta==0?new long[]{1,1,old,oldEpoch,oldEpoch,nextLoss,0}:new long[]{1,1,old,oldEpoch,oldEpoch,nextLoss,1,10001,0,0,17,1,nextDelta,0,0};nextDelta=0;activeBank=1-activeBank;epoch++;epochs[activeBank]=epoch;swapsCommitted++;point("swap-after");return new long[]{activeBank,epoch,old,oldEpoch};}
  public void acknowledgeStats(long session,int bank,long expected)throws android.os.RemoteException{validate(session);acks++;events.add("ack-attempt");point("ack-before");if(frozen==null||bank!=(int)frozen[2]||expected!=frozen[3])throw new android.os.ServiceSpecificException(116);pending=0;acksCommitted++;point("ack-after");}
 }
 static class Fixture{Object lock=new Object();List<String>events=new ArrayList<>();Memory store=new Memory(events);Remote remote=new Remote(events);Consumer consumer=new Consumer(events);Gta3xlwifiNetpolicyClient client;Gta3xlwifiStatsJournal journal;Gta3xlwifiStatsPoller poller;
 Fixture()throws Exception{client=Test.live(remote);journal=new Gta3xlwifiStatsJournal(lock,()->BOOT,store);poller=new Gta3xlwifiStatsPoller(lock,client.statsAccess(),journal);}
 void recoverSession()throws Exception{client=Test.live(remote);poller=new Gta3xlwifiStatsPoller(lock,client.statsAccess(),journal);}
 }
 public static void main(String[]args)throws Exception{
  Test.previousClientTests(args);check(Test.cases==1467);
  {var f=new Fixture();synchronized(f.lock){var a=f.poller.poll(f.consumer);check(!a.recoveredAcceptance&&f.consumer.total==10&&f.remote.acksCommitted==1&&f.store.writes==1);check(f.events.indexOf("write")<f.events.indexOf("restore=10")&&f.events.indexOf("restore=10")<f.events.indexOf("ack-attempt"));f.remote.nextDelta=20;f.poller.poll(f.consumer);check(f.consumer.total==30&&f.consumer.prepares==2&&f.remote.swapsCommitted==2&&f.remote.acksCommitted==2);}
   try{f.poller.poll(f.consumer);throw new AssertionError();}catch(IllegalStateException expected){++cases;}f.client.close();}
  for(boolean after:new boolean[]{false,true}){var f=new Fixture();f.store.before=!after;f.store.after=after;synchronized(f.lock){rejected(()->f.poller.poll(f.consumer));check(f.remote.pending!=0&&f.remote.acks==0&&f.store.writes==1);var result=f.poller.poll(f.consumer);check(result.recoveredAcceptance==after&&f.consumer.total==10&&f.remote.swapsCommitted==1&&f.remote.acksCommitted==1);check(f.consumer.prepares==(after?1:2));}f.client.close();}
  {var f=new Fixture();f.consumer.failRestoreAt=2;synchronized(f.lock){rejected(()->f.poller.poll(f.consumer));check(f.store.writes==1&&f.remote.acks==0);check(f.poller.poll(f.consumer).recoveredAcceptance&&f.consumer.prepares==1&&f.consumer.total==10&&f.remote.acksCommitted==1);}f.client.close();}
  {var f=new Fixture();f.consumer.failPrepare=true;synchronized(f.lock){rejected(()->f.poller.poll(f.consumer));check(f.store.writes==0&&f.remote.pending!=0&&f.remote.acks==0);f.poller.poll(f.consumer);check(f.consumer.total==10&&f.consumer.prepares==2&&f.remote.swapsCommitted==1);}f.client.close();}
  for(String fault:new String[]{"swap-before","swap-after","ack-before","ack-after"}){var f=new Fixture();f.remote.fault=fault;synchronized(f.lock){rejected(()->f.poller.poll(f.consumer));check(f.client.needsCompleteResnapshot()&&f.remote.held);var old=f.client;f.recoverSession();f.poller.poll(f.consumer);check(f.consumer.total==10);if(fault.startsWith("swap"))check(f.remote.swapsCommitted==1&&f.remote.acksCommitted==1);else check(f.remote.acksCommitted==(fault.equals("ack-after")?2:1));old.close();check(!f.remote.held);}
   f.client.close();}
  {var f=new Fixture();f.remote.nextLoss=1;synchronized(f.lock){rejected(()->f.poller.poll(f.consumer));check(f.remote.acks==0&&f.store.writes==0&&f.consumer.prepares==0&&f.remote.pending!=0);}f.client.close();}
  {var f=new Fixture();f.store.readFault=true;synchronized(f.lock){rejected(()->f.poller.poll(f.consumer));check(f.remote.swaps==0&&f.remote.acks==0);}f.client.close();}
  {var f=new Fixture();f.remote.epoch=5;f.remote.epochs[0]=5;synchronized(f.lock){rejected(()->f.poller.poll(f.consumer));check(f.remote.swaps==0&&f.remote.acks==0&&f.store.writes==0);}f.client.close();}
  {var f=new Fixture();synchronized(f.lock){f.poller.poll(f.consumer);byte[]saved=f.store.bytes;f.store.bytes=null;rejected(()->f.poller.poll(f.consumer));check(f.consumer.total==10&&f.remote.swaps==1&&f.remote.acks==1);f.store.bytes=saved;f.remote.nextDelta=20;f.poller.poll(f.consumer);check(f.consumer.total==30);}f.client.close();}

  // Persist metadata before first acceptance without inventing a native epoch.
  {var f=new Fixture();synchronized(f.lock){var meta=f.journal.updateState(null,ByteBuffer.allocate(8).putLong(0).array());check(meta.receipt==null&&meta.revision==1);f.remote.held=true;rejected(()->f.poller.poll(f.consumer));check(f.remote.swaps==0&&f.remote.acks==0&&!f.client.needsCompleteResnapshot());byte[]saved=f.store.bytes;f.store.bytes=null;rejected(()->f.poller.poll(f.consumer));check(f.remote.swaps==0);f.store.bytes=saved;f.remote.held=false;f.poller.poll(f.consumer);var accepted=f.journal.loadCurrentBoot();check(accepted.receipt.epoch==1&&accepted.revision==2&&f.consumer.total==10);}f.client.close();}
  // Durable UID/metadata cleanup survives restore and a later real empty poll.
  {var f=new Fixture();synchronized(f.lock){f.poller.poll(f.consumer);var old=f.journal.loadCurrentBoot();var clean=f.journal.updateState(old,ByteBuffer.allocate(8).putLong(5).array());check(clean.receipt.matches(old.receipt)&&clean.revision==2);f.consumer.total=999;f.poller.poll(f.consumer);check(f.consumer.total==5&&f.journal.loadCurrentBoot().revision==3&&f.remote.acksCommitted==2);}f.client.close();}
  // Uncertain metadata amendment is recovered from the actual accepted file,
  // never by applying the old delta again or restoring the pre-cleanup state.
  {var f=new Fixture();synchronized(f.lock){f.poller.poll(f.consumer);var old=f.journal.loadCurrentBoot();f.store.after=true;rejected(()->f.journal.updateState(old,ByteBuffer.allocate(8).putLong(5).array()));f.consumer.total=999;f.poller.poll(f.consumer);check(f.consumer.total==5&&f.consumer.prepares==2&&f.remote.acksCommitted==2);}f.client.close();}
  // Same-receipt metadata revision rollback cannot undo previously observed data.
  {var f=new Fixture();synchronized(f.lock){var first=f.journal.updateState(null,ByteBuffer.allocate(8).putLong(0).array());byte[]older=f.store.bytes;f.journal.updateState(first,ByteBuffer.allocate(8).putLong(1).array());f.remote.held=true;rejected(()->f.poller.poll(f.consumer));f.store.bytes=older;rejected(()->f.poller.poll(f.consumer));check(f.remote.swaps==0&&f.remote.acks==0);}f.client.close();}
  System.out.println("poll_cases="+cases);
 }
}
''')
sources=list((S/'java').rglob('*.java'))
for f in sources:assert sha(f)==r['inputs_sha256'][str(f)]
javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';cmd=[str(javac),'-source','21','-target','21','-d',str(O/'classes'),*map(str,sources),*map(str,O.rglob('*.java'))]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(javac.with_name('java')),'-ea','-cp',str(O/'classes'),'PollTest'],capture_output=True,text=True,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'poll_cases=(\d+)\n$',x.stdout);assert m
inputs=[Path(__file__),a.native_report,C/'report.json',J/'report.json',*sources,*O.rglob('*.java')];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'poll_cases':int(m[1]),'prior_1467_client_cases_replayed':True,'accept_install_before_ACK':True,'uncertain_write_SWAP_ACK_and_consumer_faults':True,'missing_history_not_replaced_with_zero':True,'explicit_session_recovery_no_double_counting':True,'inputs_sha256':{str(f):sha(f) for f in inputs},'command':cmd,'metadata_only_bootstrap_no_fake_receipt':True,'durable_cleanup_survives_restore':True,'metadata_revision_rollback_rejected':True,'actual_NetworkStatsFactory_consumer':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
