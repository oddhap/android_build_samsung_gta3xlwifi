
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
