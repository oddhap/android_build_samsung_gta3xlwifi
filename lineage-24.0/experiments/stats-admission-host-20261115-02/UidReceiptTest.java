
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
