
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
