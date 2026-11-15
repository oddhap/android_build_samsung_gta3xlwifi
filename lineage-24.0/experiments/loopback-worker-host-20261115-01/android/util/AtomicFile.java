package android.util;
import java.io.*;import java.nio.file.*;import java.util.*;
public class AtomicFile{
 final File file,fresh;public static boolean renameFault,flushCloses;public static final List<String>events=new ArrayList<>();
 public AtomicFile(File f){file=f;fresh=new File(f+".new");}
 public FileInputStream openRead()throws FileNotFoundException{events.add("read");File backup=new File(file+".bak");if(backup.exists())backup.renameTo(file);if(file.exists()&&fresh.exists())fresh.delete();return new FileInputStream(file);}
 public FileOutputStream startWrite()throws IOException{events.add("start");return new FileOutputStream(fresh){public void flush()throws IOException{super.flush();if(flushCloses){flushCloses=false;close();}}};}
 public void finishWrite(FileOutputStream s){events.add("finish");try{s.getFD().sync();s.close();if(renameFault){renameFault=false;return;}Files.move(fresh.toPath(),file.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(IOException e){throw new RuntimeException(e);}}
 public void failWrite(FileOutputStream s){events.add("fail");try{s.close();}catch(IOException ignored){}fresh.delete();}
}
