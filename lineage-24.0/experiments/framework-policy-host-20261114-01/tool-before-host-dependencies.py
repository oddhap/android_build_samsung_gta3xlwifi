#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run actual Java policy owner against pinned A17 queries and actual native frame parser.

Android Binder/maps/transport are explicit host fixtures. Actual Struct/key/query
sources are used; only Inet6Address.ANY is lowered to the same host zero address.
This is serialization/value/failure evidence, not device networking readiness.
"""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-source','native-report','permission-report','client-host','collector-host','owner-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();N=a.native_source.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();inputs={}
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
def put(path,text):p=O/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
def copy(path,target):bind(path);put(target,Path(path).read_text())
native=json.loads(a.native_report.read_text());assert native['passed'];bind(a.native_report);bind(a.permission_report);bind(Path(__file__))
for source in ['Gta3xlwifiNetpolicyBackend.java','Gta3xlwifiNetpolicyClient.java','Gta3xlwifiPermissionCollector.java']:
 q=S/'java/com/android/server'/source;assert sha(q)==native['inputs_sha256'][str(q)];bind(q)
# Exact previously reviewed Binder and Android UID test fixtures.
for q in (a.client_host/'android').rglob('*.java'):copy(q,str(q.relative_to(a.client_host)))
for q in (a.client_host/'com/android/internal/net').glob('*.java'):copy(q,str(q.relative_to(a.client_host)))
for q in (a.collector_host/'android/os').glob('*.java'):copy(q,str(q.relative_to(a.collector_host)))
copy(a.collector_host/'android/util/SparseIntArray.java','android/util/SparseIntArray.java')
copy(a.collector_host/'com/android/modules/utils/build/SdkLevel.java','com/android/modules/utils/build/SdkLevel.java')
put('android/os/ServiceSpecificException.java','package android.os; public class ServiceSpecificException extends RuntimeException {public final int errorCode;public ServiceSpecificException(int c){errorCode=c;}public ServiceSpecificException(int c,String m){super(m);errorCode=c;}}')
put('android/os/Build.java','package android.os; public class Build {public static class VERSION_CODES {public static final int TIRAMISU=33;}}')
put('android/system/OsConstants.java','package android.system; public class OsConstants {public static final int EINVAL=22,ENODEV=19,EAGAIN=11,ENOSPC=28,EOPNOTSUPP=95,ENOTCONN=107,ESTALE=116,EPROTO=71;}')
put('android/system/ErrnoException.java','package android.system; public class ErrnoException extends Exception {public final int errno;public ErrnoException(String m,int e){super(m);errno=e;}}')
put('android/system/Os.java','package android.system; public class Os {public static String strerror(int e){return Integer.toString(e);}}')
put('android/util/Pair.java','package android.util; public class Pair<A,B> {public final A first;public final B second;public Pair(A a,B b){first=a;second=b;}public static <A,B> Pair<A,B> create(A a,B b){return new Pair<>(a,b);}}')
put('android/util/IndentingPrintWriter.java','package android.util; public class IndentingPrintWriter extends java.io.PrintWriter {public IndentingPrintWriter(java.io.Writer w){super(w);}}')
put('android/net/MacAddress.java','package android.net; public class MacAddress {private byte[]b;public static MacAddress fromBytes(byte[]b){MacAddress a=new MacAddress();a.b=b.clone();return a;}public byte[]toByteArray(){return b.clone();}}')
for name in ['NonNull','Nullable','RequiresApi']:
 body='int value() default 0;' if name=='RequiresApi' else ''
 for package in ['android.annotation','androidx.annotation']:
  put(package.replace('.','/')+'/'+name+'.java','package '+package+'; @java.lang.annotation.Target({java.lang.annotation.ElementType.TYPE_USE,java.lang.annotation.ElementType.TYPE,java.lang.annotation.ElementType.FIELD,java.lang.annotation.ElementType.METHOD,java.lang.annotation.ElementType.PARAMETER,java.lang.annotation.ElementType.CONSTRUCTOR}) public @interface '+name+'{'+body+'}')
root=T/'packages/modules/Connectivity'
actual={'com/android/net/module/util/Struct.java':root/'staticlibs/device/com/android/net/module/util/Struct.java','android/net/BpfNetMapsConstants.java':root/'framework/src/android/net/BpfNetMapsConstants.java','android/net/BpfNetMapsUtils.java':root/'framework/src/android/net/BpfNetMapsUtils.java','android/net/UidOwnerValue.java':root/'framework/src/android/net/UidOwnerValue.java'}
for name in ['IngressDiscardKey','LocalNetAccessKey','LocalNetUidHostAllowlistKey']:actual['com/android/net/module/util/bpf/'+name+'.java']=root/('common/src/com/android/net/module/util/bpf/'+name+'.java')
for dest,source in actual.items():
 bind(source);put(dest,source.read_text().replace('Inet6Address.ANY','HostAny.address()'))
put('com/android/net/module/util/bpf/HostAny.java','package com.android.net.module.util.bpf;class HostAny {static java.net.InetAddress address(){try{return java.net.InetAddress.getByAddress(new byte[16]);}catch(Exception e){throw new AssertionError(e);}}}')
cm=root/'framework/src/android/net/ConnectivityManager.java';bind(cm)
names=set(re.findall(r'import static android.net.ConnectivityManager.(\w+);','\n'.join(p.read_text() for p in actual.values())))
constants=[]
for name in sorted(names):
 m=re.search(r'public static final int '+name+r'\s*=\s*([^;]+);',cm.read_text());assert m,name;constants.append(m[0])
put('android/net/ConnectivityManager.java','package android.net;public class ConnectivityManager{\n'+'\n'.join(constants)+'\n}')
put('com/android/net/module/util/IBpfMap.java','package com.android.net.module.util;public interface IBpfMap<K,V>{V getValue(K key)throws android.system.ErrnoException;}')
put('Test.java',r'''
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
''')
interface=a.permission_report.parent/'permission-snapshot-interface.jar';bind(interface);classes=O/'classes';classes.mkdir();javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';bind(javac)
java_sources=[S/'java/com/android/server'/name for name in ['Gta3xlwifiNetpolicyBackend.java','Gta3xlwifiNetpolicyClient.java','Gta3xlwifiPermissionCollector.java']]
cmd=[str(javac),'-source','21','-target','21','-classpath',str(interface),'-d',str(classes),*map(str,java_sources),*map(str,O.rglob('*.java'))]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-14000:]
x=subprocess.run([str(javac.with_name('java')),'-ea','-cp',str(classes)+os.pathsep+str(interface),'Test',str(O/'wire.bin')],capture_output=True,text=True,timeout=120);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.fullmatch(r'passed_cases=(\d+) frames=(\d+)\n',x.stdout);assert m
# Decode every actual Java frame through the actual native protocol/value compilers.
shutil.copyfile(a.owner_host/'IptablesRestoreController.h',O/'IptablesRestoreController.h');bind(a.owner_host/'IptablesRestoreController.h')
cpp=r'''
#include "Gta3xlwifiPolicyFrame.h"
#include <cassert>
#include <fstream>
#include <cstdio>
using namespace android::net::gta3xlwifi;
static std::ifstream stream;static unsigned cases,frames;
static uint32_t word(){unsigned char b[4];stream.read((char*)b,4);assert(stream.gcount()==4);return (uint32_t(b[0])<<24)|(uint32_t(b[1])<<16)|(uint32_t(b[2])<<8)|b[3];}
#define C(x) do{assert(x);++cases;}while(0)
int main(int argc,char**argv){assert(argc==2);stream.open(argv[1],std::ios::binary);while(stream.peek()!=EOF){auto flags=word();bool loop=word(),saver=word();std::vector<int32_t>counts;std::array<std::vector<int32_t>,10>sections;for(auto&section:sections){auto count=word();C(count<=1000000);counts.push_back(count);for(unsigned i=0;i<count;i++)section.push_back((int32_t)word());}PolicyFrame frame;C(!frame.begin(counts,flags,loop,true,saver));for(unsigned s=0;s<10;s++)for(size_t offset=0;offset<sections[s].size();offset+=4096){auto end=std::min(offset+4096,sections[s].size());C(!frame.append(s,offset,{sections[s].begin()+offset,sections[s].begin()+end}));}SocketPolicyProjection::State state;C(!frame.compile(&state));unsigned queries=word();for(unsigned q=0;q<queries;q++){int32_t uid=word();uint32_t expected=word(),actual=0;C(!state.policy.blockedReasons(uid,&actual)&&actual==expected);expected=word();C(!state.permissions.get(uid,&actual)&&actual==expected);for(int chain=1;chain<=12;chain++){int32_t rule;expected=word();C(!state.policy.getUidRule(chain,uid,&rule)&&rule==(int32_t)expected);}}unsigned prefixes=word();for(unsigned q=0;q<prefixes;q++){LocalNetworkState::Entry query{word(),{},false};for(unsigned n=0;n<6;n++){uint32_t v=word();for(unsigned k=0;k<4;k++)query.key[4*n+k]=v>>(24-8*k);}bool expected=word(),found=false,allowed=false;C(!state.local.lookup(LocalNetworkState::Table::Network,query,&found,&allowed)&&allowed==expected);}++frames;}printf("native_frames=%u native_comparisons=%u\n",frames,cases);}
''';(O/'native.cpp').write_text(cpp)
names=['Gta3xlwifiPolicyFrame','Gta3xlwifiUidPolicy','Gta3xlwifiPermissionBootstrap','Gta3xlwifiUidPermissionState','Gta3xlwifiIngressPolicy','Gta3xlwifiLocalNetworkState'];sources=[N/(n+'.cpp') for n in names]
for path in sources:bind(path)
for path in N.glob('Gta3xlwifi*.h'):bind(path)
cxx=['c++','-std=c++20','-O1','-g','-ffunction-sections','-fdata-sections','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(N),'-I'+str(O),*map(str,sources),str(O/'native.cpp'),'-Wl,--gc-sections','-o',str(O/'native')]
x=subprocess.run(cxx,capture_output=True,text=True);(O/'native-compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-10000:]
x=subprocess.run([str(O/'native'),str(O/'wire.bin')],capture_output=True,text=True,timeout=120);(O/'native-test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);match=re.fullmatch(r'native_frames=(\d+) native_comparisons=(\d+)\n',x.stdout);assert match and int(match[1])==int(m[2])
for path in [O/'Test.java',O/'native.cpp',O/'wire.bin']:bind(path)
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'java_cases':int(m[1]),'actual_Java_to_native_frames':int(match[1]),'native_comparisons':int(match[2]),'actual_A17_BpfNetMapsUtils_oracle':True,'actual_Struct_and_LNA_key_serialization':True,'permission_raw_combinations_both_loopback_modes':2048,'early_policy_buffering_and_fault_withdrawal':True,'inputs_sha256':inputs,'java_command':cmd,'native_command':cxx,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS:',m[0].strip(),match[0].strip())
