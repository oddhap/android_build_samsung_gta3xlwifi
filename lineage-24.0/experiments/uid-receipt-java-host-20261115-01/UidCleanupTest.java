
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
