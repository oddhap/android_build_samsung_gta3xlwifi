#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual acceptance journal with fault stores, real temp files and OS/AtomicFile fixtures.

Android syscall/AtomicFile boundaries are explicit fixtures, not device power-loss
or IPC execution. Production source is separately compiled against actual SDK.
"""
import argparse,fcntl,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists();lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads(a.native_report.read_text());assert r['passed'] and r['actual_lifecycle_journal_and_poller_compiled'];source=S/'java/com/android/server/Gta3xlwifiStatsJournal.java';assert sha(source)==r['inputs_sha256'][str(source)]
def put(n,t):q=O/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_text(t)
put('android/system/ErrnoException.java','package android.system;public class ErrnoException extends Exception{public ErrnoException(String s){super(s);}}')
put('android/system/StructStat.java','package android.system;public class StructStat{public int st_mode,st_uid;}')
put('android/system/OsConstants.java','package android.system;public class OsConstants{public static final int O_RDONLY=0,O_CLOEXEC=1,O_NOFOLLOW=2;public static boolean S_ISREG(int n){return (n&0xf000)==0x8000;}public static boolean S_ISDIR(int n){return (n&0xf000)==0x4000;}}')
put('android/system/Os.java',r'''package android.system;
import java.io.*;import java.nio.channels.*;import java.nio.file.*;import java.util.*;
public class Os{
 public static int syncFaultCountdown;public static Path bootFile;public static boolean badUid,badMode,badDir,openFault,closeFault,syncFault;
 public static final List<String>events=new ArrayList<>();static final Map<FileDescriptor,Object>fds=new IdentityHashMap<>();
 public static FileDescriptor open(String path,int flags,int mode)throws ErrnoException{
  if((flags&OsConstants.O_NOFOLLOW)==0)throw new AssertionError("nofollow");if(openFault)throw new ErrnoException("open");
  try{if(path.equals("/proc/sys/kernel/random/boot_id")){events.add("boot-open");var in=new FileInputStream(bootFile.toFile());fds.put(in.getFD(),in);return in.getFD();}
   events.add("directory-open");var channel=FileChannel.open(Path.of(path),StandardOpenOption.READ);var fd=new FileDescriptor();fds.put(fd,channel);return fd;
  }catch(IOException e){throw new ErrnoException("fixture open "+e);}
 }
 public static StructStat fstat(FileDescriptor fd)throws ErrnoException{Object value=fds.get(fd);if(value==null)throw new ErrnoException("bad fd");var s=new StructStat();s.st_uid=badUid?1000:0;s.st_mode=value instanceof FileInputStream?(badMode?0x4000:0x8000):(badDir?0x8000:0x4000);return s;}
 public static void fsync(FileDescriptor fd)throws ErrnoException{events.add("directory-sync");if(syncFault||(syncFaultCountdown>0&&--syncFaultCountdown==0)){syncFault=false;throw new ErrnoException("sync");}try{((FileChannel)fds.get(fd)).force(true);}catch(IOException e){throw new ErrnoException("sync "+e);}}
 public static void close(FileDescriptor fd)throws ErrnoException{events.add("directory-close");Object value=fds.remove(fd);try{((Closeable)value).close();}catch(IOException e){throw new ErrnoException("close "+e);}if(closeFault){closeFault=false;throw new ErrnoException("close");}}
 public static void reset(){badUid=badMode=badDir=openFault=closeFault=syncFault=false;events.clear();}
}
''')
put('android/util/AtomicFile.java',r'''package android.util;
import java.io.*;import java.nio.file.*;import java.util.*;
public class AtomicFile{
 final File file,fresh;public static boolean renameFault,flushCloses;public static final List<String>events=new ArrayList<>();
 public AtomicFile(File f){file=f;fresh=new File(f+".new");}
 public FileInputStream openRead()throws FileNotFoundException{events.add("read");File backup=new File(file+".bak");if(backup.exists())backup.renameTo(file);if(file.exists()&&fresh.exists())fresh.delete();return new FileInputStream(file);}
 public FileOutputStream startWrite()throws IOException{events.add("start");return new FileOutputStream(fresh){public void flush()throws IOException{super.flush();if(flushCloses){flushCloses=false;close();}}};}
 public void finishWrite(FileOutputStream s){events.add("finish");try{s.getFD().sync();s.close();if(renameFault){renameFault=false;return;}Files.move(fresh.toPath(),file.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(IOException e){throw new RuntimeException(e);}}
 public void failWrite(FileOutputStream s){events.add("fail");try{s.close();}catch(IOException ignored){}fresh.delete();}
}
''')
put('Test.java',r'''
import com.android.server.Gta3xlwifiStatsJournal;
import com.android.server.Gta3xlwifiStatsJournal.*;
import java.io.*;import java.nio.file.*;import java.security.*;import java.util.*;
import android.system.Os;import android.util.AtomicFile;
public class Test{
 static int cases;static void check(boolean b){if(!b)throw new AssertionError("case "+cases);++cases;}
 interface Action{void run()throws Exception;}
 static Exception rejected(Class<?>kind,Action fn)throws Exception{try{fn.run();throw new AssertionError("missing "+kind);}catch(Exception e){check(kind.isInstance(e));return e;}}
 static final String BOOT="00112233-4455-4677-8899-aabbccddeeff",NEXT="11112233-4455-4677-8899-aabbccddeeff";
 static class Memory implements Store{byte[]bytes;int writes;boolean before,after,drop,readError;public byte[]read()throws IOException{if(readError)throw new IOException("read");return bytes==null?null:bytes.clone();}public void writeDurably(byte[]data)throws IOException{writes++;if(before)throw new IOException("before");if(!drop)bytes=data.clone();if(after){after=false;throw new IOException("after");}}}
 static byte[] hashBody(byte[]body)throws Exception{var out=new ByteArrayOutputStream();out.write(body);out.write(MessageDigest.getInstance("SHA-256").digest(body));return out.toByteArray();}
 static byte[] forged(int magic,int ver,String boot,int bank,long epoch,int length,byte[]payload)throws Exception{var out=new ByteArrayOutputStream();var d=new DataOutputStream(out);d.writeInt(magic);d.writeInt(ver);d.writeUTF(boot);d.writeLong(1);d.writeBoolean(true);d.writeInt(bank);d.writeLong(epoch);d.writeInt(length);d.write(payload);d.flush();return hashBody(out.toByteArray());}
 public static void main(String[]args)throws Exception{
  Object lock=new Object();Memory store=new Memory();String[]boot={BOOT};var journal=new Gta3xlwifiStatsJournal(lock,()->boot[0],store);
  rejected(IllegalStateException.class,journal::loadCurrentBoot);rejected(IllegalStateException.class,()->journal.accept(journal.receipt(0,1),new byte[]{1}));
  synchronized(lock){check(journal.loadCurrentBoot()==null);byte[]state={1,2,3};var receipt=journal.receipt(0,1);var accepted=journal.accept(receipt,state);state[0]=99;check(Arrays.equals(accepted.payload(),new byte[]{1,2,3}));byte[]copy=accepted.payload();copy[0]=88;check(accepted.payload()[0]==1);check(journal.loadCurrentBoot().receipt.matches(receipt));check(journal.accept(receipt,new byte[]{1,2,3}).receipt.matches(receipt)&&store.writes==1);rejected(IOException.class,()->journal.accept(receipt,new byte[]{8}));rejected(IOException.class,()->journal.accept(journal.receipt(1,1),new byte[]{1,2,3}));check(store.writes==1);journal.accept(journal.receipt(1,2),new byte[]{4});rejected(IOException.class,()->journal.accept(receipt,new byte[]{1,2,3}));check(store.writes==2);
   journal.accept(journal.receipt(0,Long.MAX_VALUE),new byte[0]);journal.accept(journal.receipt(1,Long.MIN_VALUE),new byte[]{7});rejected(IOException.class,()->journal.accept(journal.receipt(0,7),new byte[]{7}));journal.accept(journal.receipt(0,-1),new byte[]{9});check(journal.loadCurrentBoot().receipt.epoch==-1);
   rejected(IllegalArgumentException.class,()->journal.receipt(0,0));rejected(IllegalArgumentException.class,()->journal.receipt(2,1));rejected(IllegalArgumentException.class,()->journal.accept(new Receipt(NEXT,0,1),new byte[0]));rejected(IllegalArgumentException.class,()->journal.accept(journal.receipt(0,-1),new byte[Gta3xlwifiStatsJournal.MAX_PAYLOAD+1]));
   boot[0]=NEXT;rejected(IOException.class,journal::loadCurrentBoot);boot[0]=BOOT;
  }
  // Definitive I/O failure never becomes an empty boot baseline.
  synchronized(lock){store.readError=true;rejected(IOException.class,journal::loadCurrentBoot);store.readError=false;}
  for(String bad:new String[]{"", "0-0-0-0-0", BOOT.toUpperCase(),"00112233-4455-1677-8899-aabbccddeeff","00112233-4455-4677-0899-aabbccddeeff"})rejected(IOException.class,()->new Gta3xlwifiStatsJournal(lock,()->bad,new Memory()));
  rejected(IOException.class,()->new Gta3xlwifiStatsJournal(lock,()->null,new Memory()));
  // Every truncation and bit corruption fails, even on a new boot.
  var baseline=new Memory();var j=new Gta3xlwifiStatsJournal(lock,()->BOOT,baseline);synchronized(lock){j.accept(j.receipt(0,1),new byte[]{3,4,5});byte[]valid=baseline.bytes.clone();for(int n=0;n<valid.length;n++){baseline.bytes=Arrays.copyOf(valid,n);rejected(IOException.class,j::loadCurrentBoot);}for(int n=0;n<valid.length;n++){baseline.bytes=valid.clone();baseline.bytes[n]^=1;rejected(IOException.class,j::loadCurrentBoot);}baseline.bytes=valid;}
  for(byte[]bad:new byte[][]{forged(0,2,BOOT,0,1,0,new byte[0]),forged(0x47323453,3,BOOT,0,1,0,new byte[0]),forged(0x47323453,2,"bad",0,1,0,new byte[0]),forged(0x47323453,2,BOOT,2,1,0,new byte[0]),forged(0x47323453,2,BOOT,0,0,0,new byte[0]),forged(0x47323453,2,BOOT,0,1,-1,new byte[0]),forged(0x47323453,2,BOOT,0,1,1,new byte[0]),forged(0x47323453,2,BOOT,0,1,0,new byte[]{1})}){var m=new Memory();m.bytes=bad;var q=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){rejected(IOException.class,q::loadCurrentBoot);check(m.writes==0);}}
  // Write-before and write-after failures require explicit actual-file recovery.
  for(boolean after:new boolean[]{false,true}){var m=new Memory();m.before=!after;m.after=after;var q=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){var receipt=q.receipt(0,1);rejected(IOException.class,()->q.accept(receipt,new byte[]{5}));check(m.writes==1);var saved=q.loadCurrentBoot();check(after?(saved!=null&&saved.receipt.matches(receipt)):saved==null);if(after){q.accept(receipt,new byte[]{5});check(m.writes==1);}else{m.before=false;q.accept(receipt,new byte[]{5});check(m.writes==2);}}}
  {var m=new Memory();m.drop=true;var q=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){rejected(IOException.class,()->q.accept(q.receipt(0,1),new byte[]{7}));check(q.loadCurrentBoot()==null&&m.writes==1);}}
  // A previous boot is retained until explicit new acceptance, never replayed.
  {var m=new Memory();var a=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){a.accept(a.receipt(0,1),new byte[]{7});byte[]old=m.bytes.clone();var b=new Gta3xlwifiStatsJournal(lock,()->NEXT,m);check(b.loadCurrentBoot()==null&&Arrays.equals(old,m.bytes));b.accept(b.receipt(0,1),new byte[]{8});check(b.loadCurrentBoot().payload()[0]==8);}}
  // Full payload bound, with defensive copies and exact durable recovery.
  {var m=new Memory();var q=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){byte[]large=new byte[Gta3xlwifiStatsJournal.MAX_PAYLOAD];Arrays.fill(large,(byte)33);q.accept(q.receipt(0,1),large);large[0]=44;check(q.loadCurrentBoot().payload()[0]==33&&q.loadCurrentBoot().payload().length==Gta3xlwifiStatsJournal.MAX_PAYLOAD);}}

  // Metadata can be durable before any native bank acceptance, without a fake
  // epoch. Later state amendments preserve the accepted receipt and use CAS.
  {var m=new Memory();var q=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){var meta=q.updateState(null,new byte[]{9,8});check(meta.receipt==null&&meta.revision==1&&meta.bootId.equals(BOOT)&&m.writes==1);check(q.loadCurrentBoot().receipt==null);check(q.updateState(meta,new byte[]{9,8}).revision==1&&m.writes==1);rejected(IOException.class,()->q.updateState(null,new byte[]{1}));var accepted=q.accept(q.receipt(0,1),new byte[]{9,8,10});check(accepted.receipt.epoch==1&&accepted.revision==2&&m.writes==2);var cleared=q.updateState(accepted,new byte[]{9,8});check(cleared.revision==3&&cleared.receipt.matches(accepted.receipt)&&m.writes==3);rejected(IOException.class,()->q.updateState(accepted,new byte[]{7}));rejected(IOException.class,()->q.accept(accepted.receipt,accepted.payload()));check(q.accept(cleared.receipt,cleared.payload()).revision==3&&m.writes==3);}}
  for(boolean after:new boolean[]{false,true}){var m=new Memory();var q=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){var old=q.accept(q.receipt(0,1),new byte[]{1});m.before=!after;m.after=after;rejected(IOException.class,()->q.updateState(old,new byte[]{2}));var saved=q.loadCurrentBoot();check(saved.revision==(after?2:1)&&saved.receipt.matches(old.receipt)&&saved.payload()[0]==(after?2:1));if(after){rejected(IOException.class,()->q.updateState(old,new byte[]{2}));check(q.updateState(saved,new byte[]{2}).revision==2&&m.writes==2);}else{m.before=false;check(q.updateState(old,new byte[]{2}).revision==2&&m.writes==3);}}}
  // Signed consumer revision cannot wrap, independently of unsigned native epoch.
  {var m=new Memory();byte[]body;var raw=new ByteArrayOutputStream();var out=new DataOutputStream(raw);out.writeInt(0x47323453);out.writeInt(2);out.writeUTF(BOOT);out.writeLong(Long.MAX_VALUE);out.writeByte(1);out.writeInt(0);out.writeLong(1);out.writeInt(1);out.writeByte(3);out.flush();body=raw.toByteArray();m.bytes=hashBody(body);var q=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){var saved=q.loadCurrentBoot();check(saved.revision==Long.MAX_VALUE);rejected(IOException.class,()->q.updateState(saved,new byte[]{4}));rejected(IOException.class,()->q.accept(q.receipt(1,2),new byte[]{4}));check(q.updateState(saved,new byte[]{3}).revision==Long.MAX_VALUE&&m.writes==0);}}
  // Bad version2 revision/presence fields are rejected even with valid checksums.
  for(long rev:new long[]{0,-1}){var raw=new ByteArrayOutputStream();var out=new DataOutputStream(raw);out.writeInt(0x47323453);out.writeInt(2);out.writeUTF(BOOT);out.writeLong(rev);out.writeByte(0);out.writeInt(0);out.flush();var m=new Memory();m.bytes=hashBody(raw.toByteArray());var q=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){rejected(IOException.class,q::loadCurrentBoot);}}
  {var raw=new ByteArrayOutputStream();var out=new DataOutputStream(raw);out.writeInt(0x47323453);out.writeInt(2);out.writeUTF(BOOT);out.writeLong(1);out.writeByte(2);out.writeInt(0);out.flush();var m=new Memory();m.bytes=hashBody(raw.toByteArray());var q=new Gta3xlwifiStatsJournal(lock,()->BOOT,m);synchronized(lock){rejected(IOException.class,q::loadCurrentBoot);}}
  Path root=Path.of(args[0]);Files.createDirectories(root);Path file=root.resolve("state");var fs=new Gta3xlwifiStatsJournal(lock,()->BOOT,new Gta3xlwifiStatsJournal.FileStore(file.toFile()));
  synchronized(lock){check(fs.loadCurrentBoot()==null);fs.accept(fs.receipt(0,1),new byte[]{1});check(fs.loadCurrentBoot().payload()[0]==1);AtomicFile.renameFault=true;rejected(IOException.class,()->fs.accept(fs.receipt(1,2),new byte[]{2}));check(fs.loadCurrentBoot().receipt.epoch==1);AtomicFile.flushCloses=true;rejected(IOException.class,()->fs.accept(fs.receipt(1,2),new byte[]{2}));check(AtomicFile.events.contains("fail")&&fs.loadCurrentBoot().receipt.epoch==1);Os.syncFaultCountdown=2;rejected(IOException.class,()->fs.accept(fs.receipt(1,2),new byte[]{2}));check(fs.loadCurrentBoot().receipt.epoch==2);fs.accept(fs.receipt(1,2),new byte[]{2});Os.badDir=true;rejected(IOException.class,fs::loadCurrentBoot);Os.badDir=false;Os.syncFault=Os.closeFault=true;Exception both=rejected(IOException.class,fs::loadCurrentBoot);check(both.getSuppressed().length==1);check(fs.loadCurrentBoot().payload()[0]==2);}
  // Runtime boot source uses a proc fixture, never the build server's boot UUID.
  Os.bootFile=root.resolve("proc-boot-fixture");Files.writeString(Os.bootFile,BOOT+"\n");check(Gta3xlwifiStatsJournal.readKernelBootId().equals(BOOT));
  for(String text:new String[]{BOOT,BOOT+"\nX",BOOT.toUpperCase()+"\n","bad\n",""}){Files.writeString(Os.bootFile,text);rejected(IOException.class,Gta3xlwifiStatsJournal::readKernelBootId);}Files.writeString(Os.bootFile,BOOT+"\n");Os.badUid=true;rejected(IOException.class,Gta3xlwifiStatsJournal::readKernelBootId);Os.badUid=false;Os.badMode=true;rejected(IOException.class,Gta3xlwifiStatsJournal::readKernelBootId);Os.badMode=false;Os.openFault=true;rejected(IOException.class,Gta3xlwifiStatsJournal::readKernelBootId);Os.openFault=false;
  check(Os.events.contains("directory-sync")&&AtomicFile.events.contains("finish"));System.out.println("passed_cases="+cases);
 }
}
''')
javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';java=javac.with_name('java');cmd=[str(javac),'-source','21','-target','21','-d',str(O/'classes'),str(source),*map(str,O.rglob('*.java'))]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(java),'-ea','-cp',str(O/'classes'),'Test',str(O/'filesystem')],capture_output=True,text=True,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m
paths=[Path(__file__),source,a.native_report,*O.rglob('*.java')];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'max_payload_bytes':4*1024*1024,'journal_schema_version':2,'metadata_without_fake_native_acceptance':True,'CAS_revision_preserves_cleanup_across_restore':True,'uncertain_metadata_amendments_and_revision_overflow':True,'corruption_truncation_stale_conflicting_and_unsigned_epoch_replay_checks':True,'uncertain_write_before_and_after_recovery':True,'actual_file_output_FD_sync_with_OS_AtomicFile_fixtures':True,'rename_sync_and_close_failures_not_silenced':True,'boot_identity_from_explicit_proc_fixture_not_host_proc':True,'inputs_sha256':{str(q):sha(q) for q in paths},'command':cmd,'factory_poll_pipeline_implemented':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
