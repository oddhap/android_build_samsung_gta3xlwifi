import com.android.server.*;import android.net.*;import java.io.*;import java.util.*;
public class RemovalTest {
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("removal case "+cases);cases++;}
 interface Action{void run()throws Exception;}static void bad(Action x)throws Exception{try{x.run();throw new AssertionError("Expected IO "+cases);}catch(IOException e){cases++;}}
 static class Remote extends ConsumerTest.Remote {
  Gta3xlwifiStatsJournal journal;Object lock;PollTest.Memory store;int mutations,cached,calls;boolean lost,reject,prepared,failFinal;
  Remote(List<String>e){super(e);}
  public void removeUidAccountingOnce(long session,int uid,long gen,long ep,long nonce)throws android.os.RemoteException{
   validate(session);calls++;
   if(cleanupReceipt[2]==2&&cleanupReceipt[3]==uid&&cleanupReceipt[4]==nonce&&cleanupReceipt[5]==gen&&cleanupReceipt[6]==ep){cached++;return;}
   if(reject)throw new android.os.ServiceSpecificException(116);
   try{check(Thread.holdsLock(lock));var r=journal.loadCurrentBoot();check(r.revision==nonce);byte[]p=r.payload();java.io.DataInputStream in=new java.io.DataInputStream(new java.io.ByteArrayInputStream(p,p.length-29,29));check(in.readUnsignedByte()==1&&in.readInt()==uid&&in.readLong()==gen&&in.readLong()==ep&&in.readLong()==nonce);}catch(IOException e){throw new AssertionError(e);}
   check(pending==0&&epoch==ep);events.add("remove");cleanupReceipt=new long[]{1,5,prepared?1:2,uid,nonce,gen,ep};
   if(!prepared){mutations++;rows=new long[0][];}if(failFinal)store.before=true;if(lost||prepared)throw new android.os.RemoteException("explicit mutation reply boundary");
  }
 }
 static class F{
  Object lock=new Object();List<String>events=new ArrayList<>();PollTest.Memory store=new PollTest.Memory(events);Remote remote=new Remote(events);Gta3xlwifiStatsJournal journal;Gta3xlwifiStatsConsumer c;Gta3xlwifiNetpolicyClient client;
  F()throws Exception{journal=new Gta3xlwifiStatsJournal(lock,()->PollTest.BOOT,store);remote.lock=lock;remote.journal=journal;remote.store=store;restart();}
  void restart()throws Exception{remote.client=null;remote.held=true;remote.active=false;client=Test.live(remote);c=new Gta3xlwifiStatsConsumer(lock,client.statsAccess(),journal,false,1000);}
  void remove(int...uids)throws Exception{synchronized(lock){c.removeUidAccounting(uids);}}
  void init()throws Exception{synchronized(lock){c.initializeForAdmission();}}
  NetworkStats poll()throws Exception{synchronized(lock){return c.readDetail(-1,null,-1);}}
  byte[]payload()throws Exception{synchronized(lock){return journal.loadCurrentBoot().payload();}}
  boolean intent()throws Exception{byte[]p=payload();return p.length>=29&&p[p.length-29]==1;}
 }
 public static void main(String[]args)throws Exception{
  TerminalAbortTest.main(args);
  {F f=new F();f.remove(10001,10001);check(f.remote.mutations==1&&f.remote.calls==2&&f.remote.cached==1&&!f.intent());check(f.events.indexOf("write")<f.events.indexOf("remove"));check(f.poll().size()==0);f.restart();f.init();check(f.poll().size()==0&&f.remote.mutations==1);}
  {F f=new F();f.remote.lost=true;bad(()->f.remove(10001));check(f.intent()&&f.remote.mutations==1&&f.client.needsCompleteResnapshot());f.remote.lost=false;f.remote.rows=new long[][]{{10001,123,0,17,1,7,0,0}};f.restart();f.init();check(!f.intent()&&f.remote.mutations==1&&f.remote.cached==1);check(ConsumerTest.bytes(f.poll(),"wlan0",10001,0,123)==7);}
  {F f=new F();f.remote.failFinal=true;bad(()->f.remove(10001));check(f.intent()&&f.remote.mutations==1);f.remote.failFinal=false;f.remote.rows=new long[][]{{10001,0,0,17,1,9,0,0}};f.restart();f.init();check(!f.intent()&&f.remote.mutations==1&&ConsumerTest.bytes(f.poll(),"wlan0",10001,0,0)==9);}
  {F f=new F();f.remote.prepared=true;bad(()->f.remove(10001));check(f.intent()&&f.remote.mutations==0);f.restart();bad(f::init);check(f.remote.calls==1&&f.intent());}
  {F f=new F();f.remote.reject=true;bad(()->f.remove(10001));check(!f.intent()&&f.remote.mutations==0&&f.remote.calls==1&&!f.client.needsCompleteResnapshot());f.remote.rows=new long[0][];check(ConsumerTest.bytes(f.poll(),"wlan0",10001,0,123)==100);}
  // Intent-store faults after a successful final poll: no mutation starts.
  for(boolean after:new boolean[]{false,true}){F f=new F();f.poll();f.remote.rows=new long[0][];int target=f.store.writes+2;
   // Hook the explicit Store boundary, preserving actual journal encoding/readback.
   Gta3xlwifiStatsJournal.Store hook=new Gta3xlwifiStatsJournal.Store(){public byte[]read()throws IOException{return f.store.read();}public void writeDurably(byte[]b)throws IOException{if(f.store.writes+1==target){f.store.before=!after;f.store.after=after;}f.store.writeDurably(b);}};
   f.journal=new Gta3xlwifiStatsJournal(f.lock,()->PollTest.BOOT,hook);f.remote.journal=f.journal;f.c=new Gta3xlwifiStatsConsumer(f.lock,f.client.statsAccess(),f.journal,false,1000);
   bad(()->f.remove(10001));check(f.remote.calls==0);f.restart();if(after){bad(f::init);check(f.intent()&&f.remote.calls==0);}else{f.init();check(!f.intent());}}
  // Complete kernel receipt requires durable history; missing/conflicting history rejects admission.
  {F f=new F();f.remove(10001);f.store.bytes=null;f.restart();bad(f::init);check(f.remote.mutations==1);}
  {F f=new F();f.remote.lost=true;bad(()->f.remove(10001));f.remote.cleanupReceipt[3]=10002;f.restart();bad(f::init);check(f.remote.mutations==1&&f.remote.calls==1);}
  {F f=new F();f.poll();byte[]v2=f.payload();byte[]v1=Arrays.copyOf(v2,v2.length-1);java.nio.ByteBuffer.wrap(v1).putInt(4,1);synchronized(f.lock){f.c.restore(v1);check(true);byte[]bad=v2.clone();bad[bad.length-1]=2;bad(()->f.c.restore(bad));}check(f.remote.mutations==0);}
  {F f=new F();bad(()->f.remove(-1));check(f.remote.calls==0&&f.remote.swaps==0);f.remove();check(f.remote.swaps==0);}
  {F f=new F();var a=f.client.statsAccess();f.client.close();bad(a::readUidCleanup);check(f.remote.calls==0);}
  System.out.println("durable_removal_cases="+cases);
 }
}
