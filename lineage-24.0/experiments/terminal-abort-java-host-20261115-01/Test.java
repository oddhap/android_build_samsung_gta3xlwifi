
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
  public long[] readStats(long s,int kind,int bank,long epoch)throws RemoteException {throw new UnsupportedOperationException();}
  public long[] swapStats(long s,int bank,long epoch)throws RemoteException {throw new UnsupportedOperationException();}
  public void acknowledgeStats(long s,int bank,long epoch)throws RemoteException {throw new UnsupportedOperationException();}
  public void setStatsCounterset(long s,int uid,int counterset)throws RemoteException {throw new UnsupportedOperationException();}
  public void closeSession(IBinder token)throws RemoteException {closes++;point("close-before");if(client==null||client!=token)throw new ServiceSpecificException(116);held=true;active=false;client=null;point("close-after");}
 }

 static class StatsRemote extends Remote {
  long[] reply;long[] swapReply={1,2,0,1};boolean earlyHeld;int statReads,swaps,acks,countersets;
  public long[] readStats(long s,int kind,int bank,long epoch)throws RemoteException{
   validate(s);statReads++;if(earlyHeld)throw new ServiceSpecificException(11);point("stats-read");
   if(reply!=null)return reply;
   switch(kind){case 0:return new long[]{1,0,0,1,0,0,0,1,0,0,0,0,0,0,0};
    case 1:check(bank==1&&epoch==7);return new long[]{1,1,1,7,-1,0,1,10001,0xffffffffL,1,17,Long.MIN_VALUE,-1,5,6};
    case 2:return new long[]{1,2,-1,0,1,10001,Long.MIN_VALUE,-1,5,6};
    case 3:return new long[]{1,3,-1,0,1,17,Long.MIN_VALUE,-1,5,6};default:throw new AssertionError();}
  }
  public long[] swapStats(long s,int bank,long epoch)throws RemoteException{validate(s);swaps++;point("stats-swap");check(bank==0&&epoch==1);return swapReply;}
  public void acknowledgeStats(long s,int bank,long epoch)throws RemoteException{validate(s);acks++;point("stats-ack");check(bank==1&&epoch==7);}
  public void setStatsCounterset(long s,int uid,int counterset)throws RemoteException{validate(s);countersets++;point("stats-counterset");check(uid==123&&counterset==1);}
 }
 static Gta3xlwifiNetpolicyClient live(StatsRemote r)throws Exception{
  var c=new Gta3xlwifiNetpolicyClient(r);c.start();c.publishCompleteSnapshot(frame());return c;
 }
 static void statsTests()throws Exception{
  {var r=new StatsRemote();var c=new Gta3xlwifiNetpolicyClient(r);rejected(IllegalStateException.class,c::statsAccess);c.start();var access=c.statsAccess();r.earlyHeld=true;rejected(java.io.IOException.class,access::readState);check(r.closes==0&&r.client!=null);r.earlyHeld=false;c.publishCompleteSnapshot(frame());check(!c.needsCompleteResnapshot());c.close();rejected(IllegalStateException.class,c::statsAccess);}
  {var r=new StatsRemote();var c=live(r);var a=c.statsAccess();var state=a.readState();check(state.activeBank==0&&state.activeEpoch==1&&state.pendingMask==0);long[]w=state.words();w[3]=77;check(state.words()[3]==1);var f=a.readFrozen(1,7);check(f.kind==1&&f.bank==1&&f.epoch==7&&f.sequence==-1&&f.lostUpdates==0&&f.count==1&&f.width==8);long[]row=f.row(0);check(row[0]==10001&&row[1]==0xffffffffL&&row[4]==Long.MIN_VALUE&&row[5]==-1);row[0]=0;check(f.row(0)[0]==10001);f.requireLossless();rejected(IndexOutOfBoundsException.class,()->f.row(-1));rejected(IndexOutOfBoundsException.class,()->f.row(1));check(a.readApps().row(0)[1]==Long.MIN_VALUE&&a.readInterfaces().row(0)[0]==17);check(r.acks==0&&r.swaps==0);check(Arrays.equals(a.swap(0,1),new long[]{1,2,0,1}));a.acknowledge(1,7);a.setCounterset(123,1);check(r.acks==1&&r.countersets==1&&r.swaps==1);c.close();}
  // Full native maxima are accepted with exact key ordering/immutable rows.
  for(int kind:new int[]{1,2,3}){var r=new StatsRemote();var c=live(r);var a=c.statsAccess();int max=kind==1?5000:kind==2?10000:1000;int header=kind==1?7:5,width=kind==1?8:5;r.reply=new long[header+width*max];r.reply[0]=1;r.reply[1]=kind;r.reply[header-1]=max;if(kind==1){r.reply[2]=1;r.reply[3]=7;}for(int n=0;n<max;n++){int off=header+n*width;r.reply[off]=n+1;if(kind==1){r.reply[off+1]=0xffffffffL;r.reply[off+2]=1;r.reply[off+3]=17;}r.reply[off+width-1]=n+99;}var snap=kind==1?a.readFrozen(1,7):kind==2?a.readApps():a.readInterfaces();check(snap.count==max&&snap.row(max-1)[0]==max&&snap.row(max-1)[width-1]==max+98);Arrays.fill(r.reply,77);check(snap.row(max-1)[0]==max);check(r.acks==0&&r.swaps==0);c.close();}
  // Real loss remains visible and is never converted to complete zero counters.
  {var r=new StatsRemote();var c=live(r);var a=c.statsAccess();r.reply=new long[]{1,2,7,-1,0};var snap=a.readApps();check(snap.lostUpdates==-1&&snap.count==0);rejected(java.io.IOException.class,snap::requireLossless);check(r.closes==0&&!c.needsCompleteResnapshot()&&r.acks==0);c.close();}
  // Validate state before exposing an active/pending bank identity.
  for(long[]bad:new long[][]{{1,0},{2,0,0,1,0,0,0,1,0,0,0,0,0,0,0},{1,0,2,1,0,0,0,1,0,0,0,0,0,0,0},{1,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{1,0,0,1,1,0,0,1,0,0,0,0,0,0,0},{1,0,0,1,2,0,0,1,0,0,0,0,0,0,0},{1,0,0,1,0,5001,0,1,0,0,0,0,0,0,0}}){var r=new StatsRemote();var c=live(r);r.reply=bad;rejected(java.io.IOException.class,c.statsAccess()::readState);check(r.closes==1&&r.held&&c.needsCompleteResnapshot());rejected(IllegalStateException.class,()->c.publishCompleteSnapshot(frame()));c.close();}
  {var r=new StatsRemote();var c=live(r);r.reply=new long[]{1,0,0,1,2,0,0,1,7,0,0,0,0,0,0};check(c.statsAccess().readState().pendingMask==2);c.close();}
  // Malformed table schemas, keys, counts, identities, order and duplicates.
  for(long[]bad:new long[][]{{1,2},{1,2,0,0,-1},{1,2,0,0,10001},{1,2,0,0,1},{1,2,0,0,1,-1,0,0,0,0},{1,2,0,0,2,2,0,0,0,0,1,0,0,0,0},{1,2,0,0,2,1,0,0,0,0,1,0,0,0,0}}){var r=new StatsRemote();var c=live(r);r.reply=bad;rejected(java.io.IOException.class,c.statsAccess()::readApps);check(r.held&&r.acks==0&&c.needsCompleteResnapshot());c.close();}
  for(int column:new int[]{0,1,2,3}){var r=new StatsRemote();var c=live(r);r.reply=new long[]{1,1,1,7,0,0,1,10001,7,1,17,1,2,3,4};r.reply[7+column]=column==2?2:column==0?-1:0x100000000L;rejected(java.io.IOException.class,()->c.statsAccess().readFrozen(1,7));check(r.held);c.close();}
  {var r=new StatsRemote();var c=live(r);r.reply=new long[]{1,1,0,7,0,0,0};rejected(java.io.IOException.class,()->c.statsAccess().readFrozen(1,7));check(r.held);c.close();}
  // Each uncertain mutation/read is invoked ONCE, withdraws and invalidates.
  for(String fault:new String[]{"stats-read","stats-swap","stats-ack","stats-counterset"}){var r=new StatsRemote();var c=live(r);var a=c.statsAccess();r.fault=fault;rejected(java.io.IOException.class,()->{switch(fault){case "stats-read":a.readState();break;case "stats-swap":a.swap(0,1);break;case "stats-ack":a.acknowledge(1,7);break;default:a.setCounterset(123,1);}});check(r.calls.get(fault)==1&&r.closes==1&&r.held&&c.needsCompleteResnapshot());rejected(IllegalStateException.class,c::statsAccess);c.close();}
  {var r=new StatsRemote();var c=live(r);r.swapReply=new long[]{1,3,0,1};rejected(java.io.IOException.class,()->c.statsAccess().swap(0,1));check(r.swaps==1&&r.held);c.close();}
  {var r=new StatsRemote();var c=live(r);var a=c.statsAccess();int calls=r.statReads;rejected(IllegalArgumentException.class,()->a.readFrozen(-1,1));rejected(IllegalArgumentException.class,()->a.readFrozen(0,0));rejected(IllegalArgumentException.class,()->a.swap(0,-1));rejected(IllegalArgumentException.class,()->a.swap(2,1));rejected(IllegalArgumentException.class,()->a.acknowledge(0,0));rejected(IllegalArgumentException.class,()->a.setCounterset(-1,0));rejected(IllegalArgumentException.class,()->a.setCounterset(0,2));check(r.closes==0&&r.statReads==calls);c.close();}
  // Both stats success and invalidation must complete while another thread owns
  // the Java policy-client lock (the factory's lock may be held by the caller).
  for(boolean malformed:new boolean[]{false,true}){var r=new StatsRemote();var c=live(r);var a=c.statsAccess();if(malformed)r.reply=new long[]{1,0};var field=Gta3xlwifiNetpolicyClient.class.getDeclaredField("mLock");field.setAccessible(true);Object lock=field.get(c);var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var pool=Executors.newFixedThreadPool(2);var holder=pool.submit(()->{synchronized(lock){entered.countDown();try{release.await();}catch(InterruptedException e){throw new RuntimeException(e);}}});entered.await();try{var result=pool.submit(()->{try{a.readState();return !malformed;}catch(java.io.IOException expected){return malformed;}});check(result.get(2,TimeUnit.SECONDS));}finally{release.countDown();holder.get();pool.shutdownNow();}check(c.needsCompleteResnapshot()==malformed);c.close();}
 }
 static class Oem extends Binder implements IOemNetd {Remote remote;int gets;Oem(Remote r){remote=r;}public IGta3xlwifiNetpolicy getGta3xlwifiNetpolicy(){gets++;return remote;}}
 public static void previousClientTests(String[]args)throws Exception{
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
  statsTests();
  System.out.println("passed_cases="+cases);
 }
}
