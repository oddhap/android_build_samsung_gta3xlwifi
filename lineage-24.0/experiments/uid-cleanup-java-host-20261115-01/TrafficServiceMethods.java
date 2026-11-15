import android.annotation.Nullable;import com.android.server.*;import android.net.NetworkStats;import java.io.IOException;
class TrafficServiceMethods{
 static final String TAG="fixture";static final int SET_DEFAULT=0,SET_FOREGROUND=1;
 Gta3xlwifiStatsAccess mGtaStats;Gta3xlwifiTrafficStats mGtaTrafficStats;
 final Object mStatsLock=new Object(),mContext=new Object();final Cache mActiveUidCounterSet=new Cache();
 final Maps mUidCounterSetMap=new Maps();final Deps mDeps=new Deps();
 static class Binder{static int uid;static int getCallingUid(){return uid;}}
 static class StatsResult{long rxBytes,rxPackets,txBytes,txPackets;StatsResult(long rb,long rp,long tb,long tp){rxBytes=rb;rxPackets=rp;txBytes=tb;txPackets=tp;}}
 static class Log{static void w(String t,String m){}static void w(String t,String m,Exception e){}static void wtf(String t,String m){throw new AssertionError(m);}}
 static class ErrnoException extends Exception{}
 static class S32{S32(int x){}}static class U8{U8(short x){}}
 static class Maps{void deleteEntry(S32 k)throws ErrnoException{throw new AssertionError("Unexpected BPF mutation");}void updateEntry(S32 k,U8 v)throws ErrnoException{throw new AssertionError("Unexpected BPF mutation");}}
 static class Cache{java.util.Map<Integer,Integer>m=new java.util.HashMap<>();int get(int uid,int value){return m.getOrDefault(uid,value);}void put(int uid,int set){m.put(uid,set);}}
 static class Deps{NetworkStats.Entry nativeGetUidStat(int uid){throw new AssertionError("Unexpected old JNI read");}}
 static class PermissionUtils{static void enforceNetworkStackPermission(Object c){if(Binder.uid!=1000)throw new SecurityException();}}
public StatsResult getUidStats(int uid) {
        final int callingUid = Binder.getCallingUid();
        if (callingUid != android.os.Process.SYSTEM_UID && callingUid != uid) {
            return null;
        }
        return getStatsResultFromEntryOrNull(mGtaTrafficStats == null
                ? mDeps.nativeGetUidStat(uid) : privateTrafficStats(true, uid, null));
    }
private NetworkStats.Entry privateTrafficStats(boolean uidQuery, int uid, String iface) {
        try { return uidQuery ? mGtaTrafficStats.uid(uid) : mGtaTrafficStats.iface(iface); }
        catch (IOException failure) {
            Log.w(TAG, "Private TrafficStats counters unavailable", failure);
            // Existing nullable binder result signals unsupported/unavailable, never invented zero.
            return null;
        }
    }
private StatsResult getStatsResultFromEntryOrNull(@Nullable NetworkStats.Entry entry) {
        if (entry == null) return null;
        return new StatsResult(entry.rxBytes, entry.rxPackets, entry.txBytes, entry.txPackets);
    }
private void setKernelCounterSet(int uid, int set) {
        if (mGtaStats != null) {
            try { mGtaStats.setCounterset(uid, set); }
            catch (IOException failure) {
                throw new IllegalStateException("Private counterset update failed", failure);
            }
            return;
        }
        if (mUidCounterSetMap == null) {
            Log.wtf(TAG, "Fail to set UidCounterSet: Null bpf map");
            return;
        }

        if (set == SET_DEFAULT) {
            try {
                mUidCounterSetMap.deleteEntry(new S32(uid));
            } catch (ErrnoException e) {
                Log.w(TAG, "UidCounterSetMap.deleteEntry(" + uid + ") failed with errno: " + e);
            }
            return;
        }

        try {
            mUidCounterSetMap.updateEntry(new S32(uid), new U8((short) set));
        } catch (ErrnoException e) {
            Log.w(TAG, "UidCounterSetMap.updateEntry(" + uid + ", " + set
                    + ") failed with errno: " + e);
        }
    }
public void noteUidForeground(int uid, boolean uidForeground) {
        PermissionUtils.enforceNetworkStackPermission(mContext);
        synchronized (mStatsLock) {
            final int set = uidForeground ? SET_FOREGROUND : SET_DEFAULT;
            final int oldSet = mActiveUidCounterSet.get(uid, SET_DEFAULT);
            if (oldSet != set) {
                if (mGtaStats != null) {
                    // Publish the cached private set only after genuine kernel success.
                    setKernelCounterSet(uid, set);
                    mActiveUidCounterSet.put(uid, set);
                } else {
                    mActiveUidCounterSet.put(uid, set);
                    setKernelCounterSet(uid, set);
                }
            }
        }
    }
}