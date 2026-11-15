import java.util.*;import java.io.*;
class NssMethods {
 static final boolean LOGV=false;static final String TAG="fixture";static final int FLAG_PERSIST_ALL=1,POLL_REASON_REMOVE_UIDS=2;
 Object mGtaStats=new Object();int failUid=-1;List<String>events=new ArrayList<>();
 static class Log{static void v(String t,String m){}static void e(String t,String m,Exception e){}}
 class Factory{void removePrivateUidAccounting(int[]uids)throws IOException{if(uids.length!=1)throw new AssertionError("Expected per-UID transaction");for(int uid:uids){events.add("native"+uid);if(uid==failUid)throw new IOException("Explicit unconfirmed mutation");}}void removeUidsLocked(int[]u){events.add("stockFactory");}}
 class Recorder{String name;Recorder(String n){name=n;}void removeUidsLocked(int[]u){for(int uid:u)events.add(name+uid);}}
 class Cache{void delete(int uid){events.add("cache"+uid);}}
 Factory mStatsFactory=new Factory();Recorder mUidRecorder=new Recorder("uid"),mUidTagRecorder=new Recorder("tag");Cache mActiveUidCounterSet=new Cache();
 void performPollLocked(int flags,Object event){events.add("poll");}Object maybeCreatePollEvent(int why){return null;}
 void deleteKernelTagData(int uid){events.add("stockKernel"+uid);}void test(int...uids){removeUidsLocked(uids);}
private void removeUidsLocked(int... uids) {
        if (LOGV) Log.v(TAG, "removeUidsLocked() for UIDs " + Arrays.toString(uids));

        // Perform one last poll before removing
        performPollLocked(FLAG_PERSIST_ALL, maybeCreatePollEvent(POLL_REASON_REMOVE_UIDS));

        if(mGtaStats!=null){
            // Each confirmed UID retires its recorder baseline immediately. A
            // later UID failure must not retain an already-reset UID baseline.
            for(int uid:uids){
                int[] one={uid};
                try{mStatsFactory.removePrivateUidAccounting(one);}
                catch(IOException failure){
                    Log.e(TAG,"Private UID cleanup not confirmed for "+uid
                            +"; preserving its recorder history",failure);
                    continue;
                }
                mUidRecorder.removeUidsLocked(one);mUidTagRecorder.removeUidsLocked(one);
                mActiveUidCounterSet.delete(uid);
            }
            return;
        }
        mUidRecorder.removeUidsLocked(uids);
        mUidTagRecorder.removeUidsLocked(uids);

        mStatsFactory.removeUidsLocked(uids);
        // Clear kernel stats associated with UID
        for (int uid : uids) {
            deleteKernelTagData(uid);
        }
        // TODO: Remove the UID's entries from mOpenSessionCallsPerCaller.
    }
}