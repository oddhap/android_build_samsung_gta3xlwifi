
import android.net.*;import android.util.SparseIntArray;import android.os.ServiceSpecificException;
import com.android.net.module.util.*;import com.android.net.module.util.Struct.*;import com.android.net.module.util.bpf.*;
import com.android.server.*;import com.android.server.permission.PermissionBpfMap;
import java.util.*;import java.io.*;import java.net.*;import java.nio.*;import java.lang.reflect.*;
public class Test{
 static int cases,frames;static DataOutputStream wire;
 static void check(boolean b){if(!b)throw new AssertionError("case="+cases);cases++;}
 interface Action{void run()throws Exception;}
 static void rejected(int code,Action a)throws Exception{try{a.run();throw new AssertionError("missing errno "+code);}catch(ServiceSpecificException e){check(e.errorCode==code);}}
 static SparseIntArray bits(int...v){SparseIntArray b=new SparseIntArray();for(int i=0;i<v.length;i+=2)b.put(v[i],v[i+1]);return b;}
 static Object field(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
 static class Transport implements Gta3xlwifiNetpolicyBackend.Transport{
  long generation;boolean closed,failBefore,failAfter,failQuery;int commits;Gta3xlwifiNetpolicyClient.Frame last;
  public long publish(Gta3xlwifiNetpolicyClient.Frame f){if(failBefore)throw new ServiceSpecificException(5);last=f;commits++;generation++;if(failAfter)throw new ServiceSpecificException(5);return generation;}
  public long generation(){if(failQuery)throw new ServiceSpecificException(107);return generation;}
  public void close(){closed=true;}
 }
 static class Fixture{
  final Transport transport=new Transport();final Gta3xlwifiNetpolicyBackend backend;final PermissionBpfMap receiver;
  Fixture(boolean loop){backend=new Gta3xlwifiNetpolicyBackend(transport,loop,loop,true);receiver=backend.permissionReceiver(loop);}
  void initialize(){receiver.setInitialUidPermissions(new int[]{0,10},new int[]{10001,10002,1010001},bits(0,1023,1000,1023,1000000,1023,1001000,1023,10001,4,1010001,0));}
 }
 static class MapFixture<K,V> implements IBpfMap<K,V>{final java.util.Map<K,V>values=new HashMap<>();public V getValue(K k){return values.get(k);}}
 static void capture(Fixture f,Struct...queries)throws Exception{
  Object frame=f.transport.last;int[][]s=(int[][])field(frame,"mWords");int flags=(int)field(frame,"mRuntimeFlags");boolean loop=(boolean)field(frame,"mLoopbackPermission");boolean saver=(boolean)field(frame,"mDataSaver");
  wire.writeInt(flags);wire.writeInt(loop?1:0);wire.writeInt(saver?1:0);for(int[]section:s){wire.writeInt(section.length);for(int v:section)wire.writeInt(v);}
  MapFixture<S32,U32>config=new MapFixture<>();MapFixture<S32,UidOwnerValue>owners=new MapFixture<>();MapFixture<S32,U8>dataSaver=new MapFixture<>();long enabled=0;
  for(int i=0;i<s[3].length;i+=2)if(s[3][i+1]!=0)enabled|=BpfNetMapsUtils.getMatchByFirewallChain(s[3][i]);config.values.put(BpfNetMapsConstants.UID_RULES_CONFIGURATION_KEY,new U32(enabled));dataSaver.values.put(BpfNetMapsConstants.DATA_SAVER_ENABLED_KEY,new U8((short)(saver?1:0)));
  for(int i=0;i<s[4].length;i+=2){S32 key=new S32(s[4][i+1]);UidOwnerValue old=owners.values.get(key);owners.values.put(key,new UidOwnerValue(0,(old==null?0:old.rule)|BpfNetMapsUtils.getMatchByFirewallChain(s[4][i])));}
  int[]uids={0,1000,10001,10002,20001,1010001,1001000,Integer.MAX_VALUE};wire.writeInt(uids.length);
  for(int uid:uids){int reasons=f.backend.blockedReasons(uid);check(reasons==BpfNetMapsUtils.getUidNetworkingBlockedReasons(uid,config,owners,dataSaver));wire.writeInt(uid);wire.writeInt(reasons);wire.writeInt(f.backend.permissions(uid));for(int c=1;c<=12;c++){int rule=f.backend.rule(c,uid);check(rule==BpfNetMapsUtils.getUidRule(owners,c,uid));wire.writeInt(rule);}}
  wire.writeInt(queries.length);for(Struct query:queries){byte[]b=query.writeToBytes();wire.writeInt(ByteBuffer.wrap(b).order(ByteOrder.nativeOrder()).getInt());ByteBuffer payload=ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);for(int i=4;i<28;i+=4)wire.writeInt(payload.getInt(i));wire.writeInt(f.backend.localAllowed(query)?1:0);}
  frames++;
 }
 public static void main(String[]args)throws Exception{
  wire=new DataOutputStream(new BufferedOutputStream(new FileOutputStream(args[0])));
  Fixture f=new Fixture(true);f.backend.setChain(1,true);f.backend.setRule(1,10001,1);f.backend.setIif(new int[]{10001},0,true);check(f.transport.commits==0&&!f.transport.closed);rejected(11,()->f.backend.rule(1,10001));f.initialize();check(f.transport.commits==1);capture(f);
  check(f.backend.permissions(10001)==0&&f.backend.permissions(10002)==4&&f.backend.permissions(20001)==0&&f.backend.permissions(0)==123);
  Random random=new Random(24);for(int n=0;n<50;n++){int c=1+random.nextInt(12),uid=10001+random.nextInt(3);f.backend.setChain(c,random.nextBoolean());f.backend.setRule(c,uid,random.nextBoolean()?1:2);f.backend.dataSaver(random.nextBoolean());capture(f);}
  f.backend.replaceChain(3,new int[]{10001,10001,10002});check(f.backend.matching(3).equals(Set.of(10001,10002)));f.backend.matching(3).clear();check(f.backend.matching(3).size()==2);capture(f);
  f.backend.setIif(new int[]{10001,10002},7,true);f.backend.lockdown(10001,true);f.backend.setIif(new int[]{10001},0,false);capture(f);f.backend.lockdown(10001,false);capture(f);
  InetAddress dns=InetAddress.getByName("8.8.8.8"),other=InetAddress.getByName("8.8.4.4"),any=InetAddress.getByName("::");
  Struct base=new LocalNetAccessKey(32,7,any,0,0),specific=new LocalNetAccessKey(160,7,dns,0,0),query=new LocalNetAccessKey(192,7,dns,17,53),blocked=new LocalNetAccessKey(192,7,other,17,53),absent=new LocalNetAccessKey(192,8,other,17,53);
  f.backend.local(base,false,false);f.backend.local(specific,false,true);check(f.backend.localAllowed(query)&&!f.backend.localAllowed(blocked)&&f.backend.localAllowed(absent));capture(f,query,blocked,absent);
  f.backend.local(new LocalNetUidHostAllowlistKey(10001,7),true,true);f.backend.local(new LocalNetUidHostAllowlistKey(10002,0,dns),true,true);capture(f,query);f.backend.removeHostInterface(7);capture(f,query);
  f.backend.setDiscard(dns,7);f.backend.setDiscard(InetAddress.getByName("2001:db8::1"),8);capture(f);f.backend.removeDiscard(dns);capture(f);f.backend.blockLocalUid(10001,true);check(f.backend.localUidBlocked(10001));capture(f);
  int commits=f.transport.commits;rejected(22,()->f.backend.setRule(1,-1,1));rejected(22,()->f.backend.setChain(0,true));rejected(22,()->f.backend.setDiscard(InetAddress.getByName("0.0.0.0"),7));check(f.transport.commits==commits&&!f.transport.closed);
  int[]tooMany=new int[20001];for(int i=0;i<tooMany.length;i++)tooMany[i]=i+10000;Fixture early=new Fixture(true);rejected(28,()->early.backend.replaceChain(1,tooMany));check(early.transport.commits==0&&!early.transport.closed);early.initialize();capture(early);
  for(boolean loop:new boolean[]{false,true}){Fixture a=new Fixture(loop);a.initialize();for(int raw=0;raw<1024;raw++){a.receiver.setUidsPermissionBits(bits(10001,raw));capture(a);}}
  {Fixture a=new Fixture(true);a.initialize();a.transport.generation++;rejected(116,()->a.backend.permissions(10001));check(a.transport.closed);rejected(107,()->a.backend.rule(1,10001));}
  {Fixture a=new Fixture(true);a.initialize();a.transport.failQuery=true;rejected(107,()->a.backend.blockedReasons(10001));check(a.transport.closed);}
  for(boolean after:new boolean[]{false,true}){Fixture a=new Fixture(true);a.initialize();a.transport.failBefore=!after;a.transport.failAfter=after;rejected(5,()->a.backend.setChain(1,true));check(a.transport.closed);rejected(107,()->a.backend.permissions(10001));}
  {Fixture a=new Fixture(true);a.initialize();a.receiver.removeUser(10);capture(a);a.receiver.removeAppId(10001);capture(a);}
  rejected(95,()->Gta3xlwifiNetpolicyBackend.connect(null,false,true,true,true,false,false));rejected(95,()->Gta3xlwifiNetpolicyBackend.connect(null,true,true,true,false,false,false));rejected(95,()->Gta3xlwifiNetpolicyBackend.connect(null,true,true,true,true,true,false));rejected(95,()->Gta3xlwifiNetpolicyBackend.connect(null,true,true,true,true,false,true));
  wire.close();System.out.println("passed_cases="+cases+" frames="+frames);
 }
}
