import com.android.server.*;import com.android.server.connectivity.ClatCoordinator;import android.net.*;import android.os.*;import java.io.*;import java.util.*;
public class ClatJavaTest{
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("clat java case "+cases);cases++;}interface Action{void run()throws Exception;}static void bad(Action a)throws Exception{try{a.run();throw new AssertionError();}catch(IOException e){cases++;}}
 static class Remote extends LoopbackJavaTest.Remote{int tags;ParcelFileDescriptor seen;boolean failTag;public void tagClatSocket(long session,ParcelFileDescriptor fd)throws RemoteException{validate(session);check(!fd.closed&&fd.id==101);tags++;seen=fd;if(failTag)throw new RemoteException("Explicit lost FD-tag reply");}}
 static class Deps extends ClatCoordinator.Dependencies{
  final Remote remote=new Remote();final Gta3xlwifiStatsAccess stats;final List<ParcelFileDescriptor>fds=new ArrayList<>();final List<String>events=new ArrayList<>();boolean stock;int fault,maps,cookies,starts,stops;final CookieMap cookieMap=new CookieMap();
  Deps()throws Exception{stats=Test.live(remote).statsAccess();}
  void point(int n)throws IOException{if(fault==n)throw new IOException("Explicit dependency fault "+n);}
  public Gta3xlwifiStatsAccess getGta3xlwifiClatAccess(){return stock?null:stats;}
  public INetd getNetd(){return new INetd(){public IBinder getOemNetd(){throw new AssertionError();}public void interfaceSetEnableIPv6(String n,boolean v){events.add("ipv6");}public void interfaceSetMtu(String n,int mtu){check(mtu==1472);events.add("mtu");}public void interfaceSetCfg(InterfaceConfigurationParcel p){check(p.ifName.equals("v4-wlan0")&&p.ipv4Addr.equals("192.0.0.4"));events.add("cfg");}};}
  public com.android.net.module.util.IBpfMap<com.android.net.module.util.bpf.ClatIngress6Key,com.android.net.module.util.bpf.ClatIngress6Value> getBpfIngress6Map(){maps++;if(!stock)throw new AssertionError("Private BPF ingress open");return null;}
  public com.android.net.module.util.IBpfMap<com.android.net.module.util.bpf.ClatEgress4Key,com.android.net.module.util.bpf.ClatEgress4Value> getBpfEgress4Map(){maps++;if(!stock)throw new AssertionError("Private BPF egress open");return null;}
  public com.android.net.module.util.IBpfMap<com.android.net.module.util.Struct.S64,com.android.net.module.util.bpf.CookieTagMapValue> getBpfCookieTagMap(){maps++;if(!stock)throw new AssertionError("Private cookie map open");return cookieMap;}
  public String selectIpv4Address(String a,int p)throws IOException{point(1);return "192.0.0.4";}public String generateIpv6Address(String a,String v,String p,int m)throws IOException{point(2);return "2001:db8::1";}
  public int openPacketSocket()throws IOException{point(3);return 100;}public int openRawSocket6(int mark)throws IOException{point(4);return 101;}public ParcelFileDescriptor adoptFd(int id){var p=new ParcelFileDescriptor(id);fds.add(p);return p;}
  public int getInterfaceIndex(String iface){return fault==5?0:iface.startsWith("v4-")?18:17;}
  public void addAnycastSetsockopt(FileDescriptor fd,String v,int idx)throws IOException{point(6);}public void configurePacketSocket(FileDescriptor fd,String v,int idx)throws IOException{point(7);}public int createTunInterface(String iface)throws IOException{point(8);return 102;}public int detectMtu(String p,int s,int mark)throws IOException{point(9);return 1500;}
  public int startClatd(FileDescriptor tun,FileDescriptor read,FileDescriptor write,String i,String p,String v4,String v6)throws IOException{point(10);check(fds.size()==3&&fds.stream().noneMatch(f->f.closed));check(stock?remote.tags==0:remote.tags==1);starts++;return 12345;}
  public void stopClatd(int pid){check(pid==12345);stops++;}public long getSocketCookie(FileDescriptor fd){cookies++;if(!stock)throw new AssertionError("Private SO_COOKIE call");return 555;}
  public boolean isEthernet(String iface){throw new AssertionError("Unexpected BPF offload");}public void tcQdiscAddDevClsact(int i){throw new AssertionError("Unexpected tc setup");}
 }
 static class CookieMap implements com.android.net.module.util.IBpfMap<com.android.net.module.util.Struct.S64,com.android.net.module.util.bpf.CookieTagMapValue>{int inserts,deletes;public com.android.net.module.util.bpf.CookieTagMapValue getValue(com.android.net.module.util.Struct.S64 k){return null;}public void insertEntry(com.android.net.module.util.Struct.S64 k,com.android.net.module.util.bpf.CookieTagMapValue v){check(k.val==555&&v.uid==1029&&v.tag==0);inserts++;}public boolean deleteEntry(com.android.net.module.util.Struct.S64 k){check(k.val==555);deletes++;return true;}}
 static Object tracker(ClatCoordinator c)throws Exception{var m=ClatCoordinator.class.getDeclaredMethod("getClatdTrackerForTesting");m.setAccessible(true);return m.invoke(c);}static Object field(Object o,String n)throws Exception{var f=o.getClass().getDeclaredField(n);f.setAccessible(true);return f.get(o);}
 static IpPrefix prefix(){return new IpPrefix("64:ff9b::/96");}
 public static void main(String[]args)throws Exception{
  LoopbackWorkerTest.main(args);
  {Deps d=new Deps();ClatCoordinator c=new ClatCoordinator(d);check(d.maps==0);check(c.clatStart("wlan0",100,prefix()).equals("2001:db8::1"));check(d.remote.tags==1&&d.cookies==0&&d.starts==1&&d.fds.stream().allMatch(f->f.closed));Object t=tracker(c);check(field(t,"cookie")==null&&t.toString().contains("no cookie"));bad(()->c.clatStart("wlan0",100,prefix()));c.clatStop();check(d.stops==1&&tracker(c)==null&&d.cookieMap.deletes==0);bad(c::clatStop);}
  for(int fault=1;fault<=10;fault++){Deps d=new Deps();d.fault=fault;ClatCoordinator c=new ClatCoordinator(d);bad(()->c.clatStart("wlan0",100,prefix()));check(d.fds.stream().allMatch(f->f.closed)&&d.starts==0&&d.cookies==0&&d.maps==0&&tracker(c)==null);}
  {Deps d=new Deps();d.remote.failTag=true;ClatCoordinator c=new ClatCoordinator(d);bad(()->c.clatStart("wlan0",100,prefix()));check(d.remote.tags==1&&d.remote.aborts==1&&d.starts==0&&d.fds.size()==2&&d.fds.stream().allMatch(f->f.closed));bad(()->c.clatStart("wlan0",100,prefix()));check(d.remote.tags==1&&d.starts==0&&d.fds.stream().allMatch(f->f.closed));}
  {Deps d=new Deps();ClatCoordinator c=new ClatCoordinator(d);bad(()->c.clatStart("wlan0",100,new IpPrefix("64:ff9b::/64")));check(d.fds.isEmpty()&&d.remote.tags==0);}
  {Deps d=new Deps();d.stock=true;ClatCoordinator c=new ClatCoordinator(d);check(d.maps==3);c.clatStart("wlan0",100,prefix());check(d.cookies==1&&d.remote.tags==0&&d.cookieMap.inserts==1&&field(tracker(c),"cookie").equals(555L));c.clatStop();check(d.stops==1&&d.cookieMap.deletes==1);}
  System.out.println("clat_java_cases="+cases);
 }
}
