package android.system;
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
