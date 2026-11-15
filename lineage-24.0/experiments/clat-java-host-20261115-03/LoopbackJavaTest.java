import com.android.server.*;import java.util.*;import java.io.*;import android.os.*;
public class LoopbackJavaTest {
 static int cases;static void check(boolean x){if(!x)throw new AssertionError("loopback java case "+cases);cases++;}
 interface Action{void run()throws Exception;}static void bad(Action a)throws Exception{try{a.run();throw new AssertionError();}catch(IOException e){cases++;}}
 static class Remote extends TerminalAbortTest.Remote{
  long[]wire={1,6,0,0};int consumes;boolean lost,early;
  public long[]pollLoopbackEvents(long session)throws RemoteException{validate(session);consumes++;if(early)throw new ServiceSpecificException(11);if(lost)throw new RemoteException("Explicit lost consume response");return wire==null?null:wire.clone();}
 }
 static long[]pair(){return new long[]{1,6,5,2,10001,110001,0,-1L,100,2,110001,10001,1,99,101,3};}
 public static void main(String[]args)throws Exception{
  AdmissionTest.main(args);
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();var empty=a.pollLoopbackEvents();check(empty.size()==0&&empty.lostEvents==0);r.wire=pair();var b=a.pollLoopbackEvents();check(b.size()==2&&b.lostEvents==5&&b.event(0).senderUid==10001&&b.event(0).boottimeNs==-1L&&b.event(1).result==1&&b.event(1).sequence==101);r.wire=new long[]{1,6,8,0};check(a.pollLoopbackEvents().lostEvents==8);r.wire=new long[]{1,6,8,1,10001,110001,1,77,102,7};check(a.pollLoopbackEvents().event(0).sequence==102&&r.aborts==0);}
  for(int fault=0;fault<17;fault++){Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();long[]w=pair();switch(fault){case 0:w=null;break;case 1:w=new long[0];break;case 2:w[0]=2;break;case 3:w[1]=7;break;case 4:w[3]=-1;break;case 5:w[3]=513;break;case 6:w=Arrays.copyOf(w,w.length-1);break;case 7:w=Arrays.copyOf(w,w.length+1);break;case 8:w[4]=-1;break;case 9:w[5]=0x100000000L;break;case 10:w[5]=w[4];break;case 11:w[6]=2;break;case 12:w[8]=0;break;case 13:w[14]=100;break;case 14:w[15]=1;break;case 15:w[9]=6;break;case 16:w[6]=-1;break;}r.wire=w;bad(a::pollLoopbackEvents);check(r.aborts==1&&r.consumes==1&&c.needsCompleteResnapshot());bad(a::pollLoopbackEvents);check(r.consumes==1&&r.aborts==1);}
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();r.wire=pair();a.pollLoopbackEvents();r.wire=new long[]{1,6,4,0};bad(a::pollLoopbackEvents);check(r.aborts==1);}
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();r.wire=pair();a.pollLoopbackEvents();r.wire=new long[]{1,6,5,1,10001,110001,0,1,103,3};bad(a::pollLoopbackEvents);check(r.aborts==1);}
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();r.lost=true;bad(a::pollLoopbackEvents);check(r.consumes==1&&r.aborts==1);bad(a::pollLoopbackEvents);check(r.consumes==1);}
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();r.early=true;bad(a::pollLoopbackEvents);check(r.aborts==0&&!c.needsCompleteResnapshot());r.early=false;check(a.pollLoopbackEvents().size()==0&&r.consumes==2);}
  {Remote r=new Remote();var c=Test.live(r);var a=c.statsAccess();r.wire=new long[]{1,6,-1L,1,0xffffffffL,1,0,Long.MIN_VALUE,Long.MIN_VALUE,-1L};var b=a.pollLoopbackEvents();check(b.event(0).senderUid==-1&&b.event(0).sequence==Long.MIN_VALUE&&b.lostEvents==-1L);r.wire=new long[]{1,6,0,0};bad(a::pollLoopbackEvents);check(r.aborts==1);}
  {Remote r=new Remote();var a=Test.live(r).statsAccess();r.wire=new long[4+512*6];r.wire[0]=1;r.wire[1]=6;r.wire[3]=512;for(int i=0;i<512;i++){int p=4+i*6;r.wire[p]=10001;r.wire[p+1]=110001;r.wire[p+4]=i+1;}check(a.pollLoopbackEvents().size()==512);}
  System.out.println("loopback_java_cases="+cases);
 }
}
