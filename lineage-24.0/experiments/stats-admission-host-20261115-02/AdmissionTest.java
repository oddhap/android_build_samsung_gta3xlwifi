import com.android.server.*;import com.android.server.permission.*;import android.util.*;import android.os.*;import java.util.*;
public class AdmissionTest {
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("admission case "+cases);cases++;}
 interface Action{void run()throws Exception;}static void rejected(int code,Action a)throws Exception{try{a.run();throw new AssertionError();}catch(ServiceSpecificException e){check(e.errorCode==code);}}
 static class Transport implements Gta3xlwifiNetpolicyBackend.Transport {
  int commits,aborts;long generation;boolean fail;Gta3xlwifiStatsAccess stats;Gta3xlwifiNetpolicyClient.Frame last;
  Transport()throws Exception{stats=Test.live(new ConsumerTest.Remote(new ArrayList<>())).statsAccess();}
  public boolean requiresStatsAdmission(){return true;}public Gta3xlwifiStatsAccess statsAccess(){return stats;}
  public long publish(Gta3xlwifiNetpolicyClient.Frame f)throws RemoteException{commits++;last=f;if(fail)throw new RemoteException("explicit publish fault");return ++generation;}
  public long generation(){return generation;}public void close(){aborts++;}public void abort(){aborts++;}
 }
 static void permissions(PermissionBpfMap r){SparseIntArray bits=new SparseIntArray();bits.put(0,1023);bits.put(1000,1023);bits.put(10001,4);r.setInitialUidPermissions(new int[]{0},new int[]{10001},bits);}
 public static void main(String[]args)throws Exception{
  RemovalTest.main(args);
  {Transport t=new Transport();var b=new Gta3xlwifiNetpolicyBackend(t,true,true,true);var r=b.permissionReceiver(true);permissions(r);b.setChain(1,true);b.setRule(1,10001,1);b.dataSaver(true);check(t.commits==0);rejected(11,()->b.permissions(10001));b.completeStatsAdmission();check(t.commits==1&&t.aborts==0&&b.rule(1,10001)==1);java.lang.reflect.Field f=t.last.getClass().getDeclaredField("mDataSaver");f.setAccessible(true);check((boolean)f.get(t.last));b.completeStatsAdmission();check(t.commits==1);b.setChain(1,false);check(t.commits==2);}
  {Transport t=new Transport();var b=new Gta3xlwifiNetpolicyBackend(t,true,true,true);b.completeStatsAdmission();check(t.commits==0);permissions(b.permissionReceiver(true));check(t.commits==1);}
  {Transport t=new Transport();ConsumerTest.Remote remote=new ConsumerTest.Remote(new ArrayList<>());remote.cleanupReceipt=new long[]{1,5,1,10001,7,1,2};t.stats=Test.live(remote).statsAccess();var b=new Gta3xlwifiNetpolicyBackend(t,true,true,true);permissions(b.permissionReceiver(true));rejected(107,b::completeStatsAdmission);check(t.commits==0&&t.aborts==1);rejected(107,()->b.permissions(10001));}
  {Transport t=new Transport();t.fail=true;var b=new Gta3xlwifiNetpolicyBackend(t,true,true,true);permissions(b.permissionReceiver(true));rejected(107,b::completeStatsAdmission);check(t.commits==1&&t.aborts==1);rejected(107,()->b.permissions(10001));}
  {NssMethods n=new NssMethods();n.test(10001,10002);check(n.events.equals(List.of("poll","native10001","uid10001","tag10001","cache10001","native10002","uid10002","tag10002","cache10002")));}
  {NssMethods n=new NssMethods();n.failUid=10002;n.test(10001,10002,10003);check(n.events.equals(List.of("poll","native10001","uid10001","tag10001","cache10001","native10002","native10003","uid10003","tag10003","cache10003")));}
  {NssMethods n=new NssMethods();n.failUid=10001;n.test(10001);check(n.events.equals(List.of("poll","native10001")));}
  {NssMethods n=new NssMethods();n.mGtaStats=null;n.test(10001);check(n.events.equals(List.of("poll","uid10001","tag10001","stockFactory","stockKernel10001")));}
  System.out.println("admission_service_cases="+cases);
 }
}
