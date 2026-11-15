
import com.android.server.*;import com.android.server.net.*;import android.content.Context;import android.net.*;import java.io.*;import java.nio.file.*;import java.util.*;
public class FactoryTest{
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("factory case "+cases);++cases;}
 static class Deps extends NetworkStatsFactory.Dependencies{
  final BpfNetMaps maps;boolean legacy=true;int summaries;
  Deps(BpfNetMaps m){maps=m;}public boolean isLegacyNetworking(){return legacy;}
  public BpfNetMaps createBpfNetMaps(Context c){return maps;}
  public boolean isFeatureNotChickenedOut(Context c,String n){return false;}
  public int getDeviceConfigPropertyInt(String n,int d){return d;}
  public NetworkStats getNetworkStatsDetail(){throw new AssertionError("Private path attempted old JNI/proc counters");}
  public NetworkStats getNetworkStatsDev(){summaries++;return new NetworkStats(1000,0);}
 }
 public static void main(String[]args)throws Exception{
  ConsumerTest.main(args);
  Path root=Files.createTempDirectory("actual-factory-");android.system.Os.bootFile=root.resolve("boot-id");Files.writeString(android.system.Os.bootFile,PollTest.BOOT+"\n");
  ConsumerTest.Remote remote=new ConsumerTest.Remote(new ArrayList<>());Gta3xlwifiNetpolicyClient client=Test.live(remote);
  BpfNetMaps maps=new BpfNetMaps(client.statsAccess());Deps deps=new Deps(maps);NetworkStatsFactory factory=new NetworkStatsFactory(new Context(),deps);
  check(maps.captures==1);try{factory.readNetworkStatsDetail();throw new AssertionError();}catch(IOException expected){cases++;}
  java.lang.reflect.Field dataLock=NetworkStatsFactory.class.getDeclaredField("mPersistentDataLock");dataLock.setAccessible(true);maps.factoryLock=dataLock.get(factory);
  Path dir=Files.createDirectory(root.resolve("netstats"));factory.initializePrivateStats(dir.toFile());check(maps.admissions==1);factory.noteStackedIface("v4-wlan0","wlan0");factory.updateUnderlyingNetworkInfos(new UnderlyingNetworkInfo[0]);
  NetworkStats result=factory.readNetworkStatsDetail(10001,new String[]{"wlan0"},123);
  check(result.size()==1&&result.getValues(0,null).tag==123&&result.getValues(0,null).rxBytes==100&&remote.acksCommitted==1);
  check(Files.size(dir.resolve("gta3xlwifi-packet-state"))>100&&maps.captures==1&&deps.summaries==0);
  check(factory.readNetworkStatsSummaryXt().getValues(0,null).rxBytes==100&&deps.summaries==0&&maps.captures==1);
  StringWriter text=new StringWriter();factory.dump(new android.util.IndentingPrintWriter(text));check(text.toString().contains("durable revision=")&&text.toString().contains("rawRows=2"));
  remote.rows=new long[0][];factory.removeUidsLocked(new int[]{10001});check(factory.readNetworkStatsDetail().size()==0);
  // Execute the actual factory while another thread holds the real Java client lock.
  java.lang.reflect.Field field=Gta3xlwifiNetpolicyClient.class.getDeclaredField("mLock");field.setAccessible(true);Object clientLock=field.get(client);
  java.util.concurrent.FutureTask<NetworkStats> task=new java.util.concurrent.FutureTask<>(factory::readNetworkStatsDetail);
  synchronized(clientLock){Thread worker=new Thread(task);worker.start();check(task.get(3,java.util.concurrent.TimeUnit.SECONDS).size()==0);}
  check(maps.captures==1);
  // Same-boot new framework instance uses a new policy token but identical durable counters.
  remote.client=null;remote.held=true;remote.active=false;Gta3xlwifiNetpolicyClient next=Test.live(remote);NetworkStatsFactory replacement=new NetworkStatsFactory(new Context(),new Deps(new BpfNetMaps(next.statsAccess())));replacement.initializePrivateStats(dir.toFile());check(replacement.readNetworkStatsDetail().size()==0);
  try{replacement.initializePrivateStats(dir.toFile());throw new AssertionError();}catch(IllegalStateException expected){cases++;}
  Deps stock=new Deps(new BpfNetMaps(null));stock.legacy=false;NetworkStatsFactory ordinary=new NetworkStatsFactory(new Context(),stock);ordinary.initializePrivateStats(new File("/nonexistent"));check(ordinary.readNetworkStatsSummaryXt().size()==0&&stock.summaries==1&&stock.maps.captures==0);
  System.out.println("factory_cases="+cases);
 }
}
