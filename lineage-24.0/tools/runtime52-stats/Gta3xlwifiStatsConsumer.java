/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server;

import android.net.NetworkStats;
import android.net.UnderlyingNetworkInfo;
import android.os.SystemClock;
import android.util.Log;
import java.io.*;
import java.util.*;

/** Complete private factory state, using the existing factory data lock only. @hide */
public final class Gta3xlwifiStatsConsumer implements Gta3xlwifiStatsPoller.Consumer {
    private static final String TAG = "Gta3xlwifiStats";
    private static final int MAGIC = 0x47534332, VERSION = 2;
    private static final int MAX_ROWS = 20000, MAX_METADATA = 1000;
    private static final int MAX_BYTES = 4 * 1024 * 1024;
    /** Same bound as A17 netdbpf/BpfNetworkStats.h MAX_UNKNOWN_IFACE_BYTES. */
    static final long MAX_UNKNOWN_IFACE_BYTES = 100 * 1000;

    /**
     * A17 BpfNetworkStats.cpp drops every stats row whose ifindex has no entry in the
     * interface-name map (consume() deletes it: "these stats will be lost/deleted") and
     * maybeLogUnknownIface() logs one error per read once the dropped traffic reaches
     * MAX_UNKNOWN_IFACE_BYTES. Rows with ifindex 0 (traffic without a resolvable device)
     * occur on real Wi-Fi; failing the whole read instead crashed system_server through
     * the battery-stats Wi-Fi collector. Returns the new running total, or -1 once logged.
     */
    static long noteUnknownIface(long total, long ifindex, long rxBytes, long txBytes) {
        if (total < 0) return total;
        // Unsigned kernel counters above Long.MAX_VALUE saturate; this is a log bound only.
        long rx = rxBytes < 0 ? Long.MAX_VALUE : rxBytes, tx = txBytes < 0 ? Long.MAX_VALUE : txBytes;
        long sum = total + rx;
        if (sum < 0) sum = Long.MAX_VALUE;
        sum += tx;
        if (sum < 0) sum = Long.MAX_VALUE;
        if (sum >= MAX_UNKNOWN_IFACE_BYTES) {
            Log.e(TAG, "Unknown name for ifindex " + ifindex + " with more than " + sum
                    + " bytes of traffic");
            return -1;
        }
        return sum;
    }
    private final Object mLock;
    private final Gta3xlwifiStatsAccess mStats;
    private final Gta3xlwifiStatsJournal mJournal;
    private final Gta3xlwifiStatsPoller mPoller;
    private final boolean mThrottle;
    private final int mThreshold;
    private State mState;
    private long mRevision;
    private boolean mInitialized;
    private static final class Removal {
        final int uid;final long generation,epoch,nonce;
        Removal(int uid,long generation,long epoch,long nonce) throws IOException {
            if(uid<0||generation<0||epoch==0||nonce<=0)throw new IOException("Invalid UID intent");
            this.uid=uid;this.generation=generation;this.epoch=epoch;this.nonce=nonce;
        }
        boolean matches(Gta3xlwifiStatsAccess.UidCleanupReceipt r) {
            return r.phase==2&&r.uid==uid&&r.generation==generation&&r.activeEpoch==epoch&&r.nonce==nonce;
        }
    }

    private static final class State {
        NetworkStats raw = new NetworkStats(0, 0);
        NetworkStats adjusted = new NetworkStats(0, 0);
        final TreeMap<Integer, TreeSet<Integer>> tags = new TreeMap<>();
        final TreeMap<String, String> stacked = new TreeMap<>();
        Removal removal;
        UnderlyingNetworkInfo[] vpns = new UnderlyingNetworkInfo[0];
        State copy() {
            State copy = new State();
            copy.raw = raw.clone(); copy.adjusted = adjusted.clone();
            tags.forEach((uid, set) -> copy.tags.put(uid, new TreeSet<>(set)));
            copy.stacked.putAll(stacked); copy.vpns = vpns.clone(); copy.removal=removal;
            return copy;
        }
    }
    public Gta3xlwifiStatsConsumer(Object lock, Gta3xlwifiStatsAccess stats,
            Gta3xlwifiStatsJournal journal, boolean throttle, int threshold) {
        mLock = Objects.requireNonNull(lock); mStats = Objects.requireNonNull(stats);
        mJournal = Objects.requireNonNull(journal); mThrottle = throttle;
        if (threshold < 0 || threshold > MAX_ROWS) throw new IllegalArgumentException("Tag threshold");
        mThreshold = threshold; mPoller = new Gta3xlwifiStatsPoller(lock, stats, journal);
    }
    private void requireLock() {
        if (!Thread.holdsLock(mLock)) throw new IllegalStateException("Factory data lock required");
    }
    private Gta3xlwifiStatsJournal.Record load() throws IOException {
        requireLock();
        Gta3xlwifiStatsJournal.Record r = mJournal.loadCurrentBoot();
        if ((r == null && mRevision != 0) || (r != null && r.revision < mRevision)) {
            throw new IOException("Factory state disappeared or regressed");
        }
        restore(r == null ? null : r.payload());
        if (r != null) {
            if(mState.removal!=null&&mState.removal.nonce>r.revision)throw new IOException("Future UID intent nonce");
            mRevision = r.revision;
        }
        return r;
    }
    private Gta3xlwifiStatsJournal.Record amend(Gta3xlwifiStatsJournal.Record expected, State next) throws IOException {
        Gta3xlwifiStatsJournal.Record r = mJournal.updateState(expected, encode(next));
        restore(r.payload()); mRevision = r.revision;return r;
    }
    private void ensureInitialized() throws IOException {
        requireLock();if(!mInitialized)initializeForAdmission();
    }
    /** Validate actual current-boot state before any first policy publication. */
    public void initializeForAdmission() throws IOException {
        requireLock();if(mInitialized)return;
        Gta3xlwifiStatsJournal.Record r=load();
        Gta3xlwifiStatsAccess.UidCleanupReceipt receipt=mStats.readUidCleanup();
        if(mState.removal!=null)r=recoverCompleted(r,receipt);
        else if(receipt.phase==1)throw new IOException("Unresolved prepared kernel UID removal");
        if(receipt.phase==2&&(r==null||Long.compareUnsigned(receipt.nonce,r.revision)>=0)) {
            throw new IOException("Missing or regressed durable UID-removal history");
        }
        mInitialized=true;
    }
    private static void removeLocal(State state,int uid) {
        int[] uids={uid};state.raw.removeUids(uids);state.adjusted.removeUids(uids);state.tags.remove(uid);
    }
    private Gta3xlwifiStatsJournal.Record recoverCompleted(Gta3xlwifiStatsJournal.Record r,
            Gta3xlwifiStatsAccess.UidCleanupReceipt receipt) throws IOException {
        Removal intent=mState.removal;
        if(r==null||intent==null||!intent.matches(receipt)) {
            throw new IOException("UID intent has no matching completed kernel receipt; no replay allowed");
        }
        // Identical completed request: native verifies cached completion BEFORE
        // today's generation fence and performs no socket/counter deletion.
        mStats.removeUidAccountingOnce(intent.uid,intent.generation,intent.epoch,intent.nonce);
        State next=mState.copy();removeLocal(next,intent.uid);next.removal=null;
        return amend(r,next);
    }
    private Gta3xlwifiStatsJournal.Record settled() throws IOException {
        Gta3xlwifiStatsJournal.Record r=load();
        return mState.removal==null?r:recoverCompleted(r,mStats.readUidCleanup());
    }
    /** Full UID/socket/kernel/consumer transaction on the existing factory lock. */
    public void removeUidAccounting(int[] uids) throws IOException {
        ensureInitialized();TreeSet<Integer> targets=new TreeSet<>();
        for(int uid:uids){if(uid<0)throw new IOException("Negative removal UID");targets.add(uid);}
        if(targets.isEmpty())return;
        // Final real poll/accept/ACK must succeed before any UID removal intent.
        readDetail(NetworkStats.UID_ALL,NetworkStats.INTERFACES_ALL,NetworkStats.TAG_ALL);
        for(int uid:targets) {
            Gta3xlwifiStatsJournal.Record previous=settled();
            if(previous==null||previous.receipt==null||previous.revision==Long.MAX_VALUE)
                throw new IOException("Missing UID-removal acceptance baseline");
            Gta3xlwifiStatsAccess.State nativeState=mStats.readState();
            long epoch=previous.receipt.epoch+1;
            if(epoch==0||nativeState.activeEpoch!=epoch||nativeState.pendingMask!=0)
                throw new IOException("UID removal has unaccepted native statistics");
            long generation=mStats.generation();
            if(generation<=0)throw new IOException("Initial policy is not published");
            Removal intent=new Removal(uid,generation,epoch,previous.revision+1);
            State pending=mState.copy();pending.removal=intent;
            Gta3xlwifiStatsJournal.Record prepared=amend(previous,pending);
            try { mStats.removeUidAccountingOnce(uid,generation,epoch,intent.nonce); }
            catch(Gta3xlwifiStatsAccess.UidCleanupRejectedException rejected) {
                Gta3xlwifiStatsAccess.UidCleanupReceipt actual=mStats.readUidCleanup();
                if(intent.matches(actual)){recoverCompleted(prepared,actual);continue;}
                if(actual.phase!=1&&Long.compareUnsigned(actual.nonce,intent.nonce)<0) {
                    // Proven not started: remove only the intent. Keep all data,
                    // and let the caller observe rejection; never refresh/retry
                    // a generation that might represent a reused UID.
                    State rollback=mState.copy();rollback.removal=null;amend(prepared,rollback);
                }
                throw rejected;
            }
            recoverCompleted(prepared,mStats.readUidCleanup());
        }
    }
    @Override public void restore(byte[] complete) throws IOException {
        requireLock();
        // Decode and validate every field before publishing any part of the state.
        mState = complete == null ? new State() : decode(complete);
    }
    @Override public byte[] prepare(Gta3xlwifiStatsAccess.Snapshot frozen) throws IOException {
        requireLock();
        if (mState == null || frozen.kind != 1) throw new IOException("Missing frozen baseline");
        frozen.requireLossless();
        Map<Long, String> names = names(mStats.readInterfaceNames());
        State next = mState.copy();
        NetworkStats diff = new NetworkStats(SystemClock.elapsedRealtime(), frozen.count);
        long unknown = 0;
        for (int i = 0; i < frozen.count; ++i) {
            long[] row = frozen.row(i);
            String iface = names.get(row[3]);
            if (iface == null) {
                // As A17 parseBpfNetworkStatsDetailInternal: the ACK consumes the bank,
                // so these stats are lost/deleted exactly like the upstream consume().
                unknown = noteUnknownIface(unknown, row[3], row[5], row[7]);
                continue;
            }
            NetworkStats.Entry entry = new NetworkStats.Entry(iface, (int) row[0],
                    (int) row[2], (int) row[1], 0, 0, 0,
                    counter(row[5]), counter(row[4]), counter(row[7]), counter(row[6]), 0);
            checkedCombine(diff, entry);
            // Match the actual A17 BpfNetworkStats.cpp tagged-to-tag0 aggregation.
            if (entry.tag != 0) { entry.tag = 0; checkedCombine(diff, entry); }
        }
        NetworkStats filtered = new NetworkStats(diff.getElapsedRealtime(), diff.size());
        for (int i = 0; i < diff.size(); ++i) {
            NetworkStats.Entry entry = diff.getValues(i, null);
            if (mThrottle && entry.tag != 0) {
                TreeSet<Integer> tags = next.tags.computeIfAbsent(entry.uid, k -> new TreeSet<>());
                if (!tags.contains(entry.tag) && tags.size() >= mThreshold) continue;
                tags.add(entry.tag);
            }
            checkedCombine(filtered, entry);
        }
        merge(next.raw, filtered);
        // Keep the current A17 order: raw accumulation, then464xlat, then VPN/debug filtering.
        checkClatRange(filtered);
        filtered.apply464xlatAdjustments(next.stacked);
        for (UnderlyingNetworkInfo vpn : next.vpns) {
            checkVpnRange(filtered);
            filtered.migrateTun(vpn.getOwnerUid(), vpn.getInterface(), vpn.getUnderlyingInterfaces());
            filtered.filterDebugEntries();
        }
        merge(next.adjusted, filtered);
        return encode(next);
    }
    public NetworkStats readDetail(int uid, String[] ifaces, int tag) throws IOException {
        requireLock();
        // load also detects loss of metadata-only state before the first receipt.
        ensureInitialized();settled();
        Gta3xlwifiStatsPoller.Result result = mPoller.poll(this);
        mRevision = result.accepted.revision;
        return mState.adjusted.filteredClone(uid, ifaces, tag);
    }
    public NetworkStats readSummary() throws IOException {
        requireLock();ensureInitialized();settled();
        Gta3xlwifiStatsAccess.Snapshot interfaces = mStats.readInterfaces();
        interfaces.requireLossless();
        Map<Long, String> names = names(mStats.readInterfaceNames());
        NetworkStats out = new NetworkStats(SystemClock.elapsedRealtime(), interfaces.count);
        long unknown = 0;
        for (int i = 0; i < interfaces.count; ++i) {
            long[] row = interfaces.row(i); String iface = names.get(row[0]);
            if (iface == null) {
                // As A17 parseBpfNetworkStatsDevInternal: skip rows without an interface name.
                unknown = noteUnknownIface(unknown, row[0], row[2], row[4]);
                continue;
            }
            checkedCombine(out, new NetworkStats.Entry(iface, NetworkStats.UID_ALL,
                    NetworkStats.SET_ALL, 0, 0, 0, 0, counter(row[2]), counter(row[1]),
                    counter(row[4]), counter(row[3]), 0));
        }
        return out;
    }
    public void noteStackedIface(String stacked, String base) throws IOException {
        ensureInitialized();Gta3xlwifiStatsJournal.Record r = settled();
        if (stacked == null || base == null) return;
        name(stacked); name(base); State next = mState.copy();
        String prior = next.stacked.put(stacked, base);
        if (prior != null && !prior.equals(base)) throw new IOException("Stacked interface reassigned");
        amend(r, next);
    }
    public void updateUnderlyingNetworkInfos(UnderlyingNetworkInfo[] vpns) throws IOException {
        ensureInitialized();Gta3xlwifiStatsJournal.Record r = settled(); State next = mState.copy();
        next.vpns = Objects.requireNonNull(vpns).clone(); amend(r, next);
    }
    public void removeUids(int[] uids) throws IOException {
        ensureInitialized();Gta3xlwifiStatsJournal.Record r = settled(); State next = mState.copy();
        for (int uid : uids) {
            if (uid < 0) throw new IOException("Negative removal UID"); next.tags.remove(uid);
        }
        next.raw.removeUids(uids); next.adjusted.removeUids(uids); amend(r, next);
    }
    public void apply464xlatAdjustments(NetworkStats base, NetworkStats stacked) throws IOException {
        ensureInitialized();settled(); NetworkStats.apply464xlatAdjustments(base, stacked, mState.stacked);
    }
    public void dump(PrintWriter out) throws IOException {
        ensureInitialized();settled();
        out.println("Private frozen-bank statistics: durable revision=" + mRevision
                + " rawRows=" + mState.raw.size() + " adjustedRows=" + mState.adjusted.size());
        out.println("Distinct tagged UIDs=" + mState.tags.size()
                + " stackedInterfaces=" + mState.stacked.size() + " VPNs=" + mState.vpns.length);
    }
    private static void checkClatRange(NetworkStats stats) throws IOException {
        try {
            for (int i = 0; i < stats.size(); ++i) {
                NetworkStats.Entry e = stats.getValues(i, null);
                if (e.iface.startsWith("v4-")) {
                    Math.addExact(e.rxBytes, Math.multiplyExact(e.rxPackets, 20));
                    Math.addExact(e.txBytes, Math.multiplyExact(e.txPackets, 20));
                }
            }
        } catch (ArithmeticException overflow) { throw new IOException("464xlat counter overflow", overflow); }
    }
    private static void checkVpnRange(NetworkStats stats) throws IOException {
        // A17's unchanged VPN algorithm has unchecked aggregate/debug additions.
        // Reserve headroom for its transient copies; fail explicitly above range.
        long[] total = new long[5];
        for (int i = 0; i < stats.size(); ++i) {
            NetworkStats.Entry e = stats.getValues(i, null);
            long[] values = {e.rxBytes, e.rxPackets, e.txBytes, e.txPackets, e.operations};
            for (int c = 0; c < values.length; ++c) {
                if (values[c] < 0 || values[c] > Long.MAX_VALUE / 4 - total[c]) {
                    throw new IOException("VPN adjustment exceeds supported counter range");
                }
                total[c] += values[c];
            }
        }
    }
    private static Map<Long, String> names(Gta3xlwifiStatsAccess.Snapshot names) throws IOException {
        if (names.kind != 4) throw new IOException("Wrong interface-name schema");
        names.requireLossless(); Map<Long, String> out = new HashMap<>();
        for (int i = 0; i < names.count; ++i) out.put(names.row(i)[0], names.interfaceName(i));
        return out;
    }
    private static long counter(long value) throws IOException {
        if (value < 0) throw new IOException("Unsigned counter exceeds NetworkStats range");
        return value;
    }
    private static void checkedCombine(NetworkStats stats, NetworkStats.Entry entry) throws IOException {
        try {
            counter(entry.rxBytes); counter(entry.rxPackets); counter(entry.txBytes);
            counter(entry.txPackets); counter(entry.operations);
            int index = stats.findIndex(entry.iface, entry.uid, entry.set, entry.tag,
                    entry.metered, entry.roaming, entry.defaultNetwork);
            if (index >= 0) {
                NetworkStats.Entry old = stats.getValues(index, null);
                Math.addExact(old.rxBytes, entry.rxBytes); Math.addExact(old.rxPackets, entry.rxPackets);
                Math.addExact(old.txBytes, entry.txBytes); Math.addExact(old.txPackets, entry.txPackets);
                Math.addExact(old.operations, entry.operations);
            } else if (stats.size() >= MAX_ROWS) throw new IOException("Factory row capacity exceeded");
            stats.combineValues(entry);
        } catch (ArithmeticException overflow) { throw new IOException("NetworkStats counter overflow", overflow); }
    }
    private static void merge(NetworkStats total, NetworkStats delta) throws IOException {
        for (int i = 0; i < delta.size(); ++i) checkedCombine(total, delta.getValues(i, null));
        total.setElapsedRealtime(delta.getElapsedRealtime());
    }
    private static int count(int value, int max) throws IOException {
        if (value < 0 || value > max) throw new IOException("Invalid factory count"); return value;
    }
    private static String name(String value) throws IOException {
        if (value == null || value.length() < 1 || value.length() > 15
                || value.equals(".") || value.equals("..")) throw new IOException("Invalid interface name");
        for (char c : value.toCharArray()) if (c <= 32 || c >= 127 || c == '/' || c == ':') {
            throw new IOException("Invalid interface byte");
        }
        return value;
    }
    private static void writeStats(DataOutputStream out, NetworkStats stats) throws IOException {
        if (stats.getElapsedRealtime() < 0) throw new IOException("Invalid elapsed time");
        out.writeLong(stats.getElapsedRealtime()); out.writeInt(count(stats.size(), MAX_ROWS));
        for (int i = 0; i < stats.size(); ++i) {
            NetworkStats.Entry e = stats.getValues(i, null); out.writeUTF(name(e.iface));
            if (e.uid < 0 || e.set < 0 || e.set > 1 || e.metered != 0 || e.roaming != 0
                    || e.defaultNetwork != 0) throw new IOException("Invalid persisted row identity");
            out.writeInt(e.uid); out.writeInt(e.set); out.writeInt(e.tag);
            out.writeLong(counter(e.rxBytes)); out.writeLong(counter(e.rxPackets));
            out.writeLong(counter(e.txBytes)); out.writeLong(counter(e.txPackets));
            out.writeLong(counter(e.operations));
        }
    }
    private static NetworkStats readStats(DataInputStream in) throws IOException {
        long elapsed = counter(in.readLong()); int rows = count(in.readInt(), MAX_ROWS);
        NetworkStats stats = new NetworkStats(elapsed, rows);
        for (int i = 0; i < rows; ++i) {
            String iface = name(in.readUTF()); int uid = in.readInt(), set = in.readInt(), tag = in.readInt();
            if (uid < 0 || set < 0 || set > 1) throw new IOException("Invalid row key");
            NetworkStats.Entry e = new NetworkStats.Entry(iface, uid, set, tag, 0, 0, 0,
                    counter(in.readLong()), counter(in.readLong()), counter(in.readLong()),
                    counter(in.readLong()), counter(in.readLong()));
            if (stats.findIndex(iface, uid, set, tag, 0, 0, 0) >= 0) throw new IOException("Duplicate row");
            stats.combineValues(e);
        }
        return stats;
    }
    private byte[] encode(State state) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(MAGIC); out.writeInt(VERSION); out.writeBoolean(mThrottle); out.writeInt(mThreshold);
            writeStats(out, state.raw); writeStats(out, state.adjusted);
            out.writeInt(count(state.tags.size(), MAX_ROWS));
            for (Map.Entry<Integer, TreeSet<Integer>> tags : state.tags.entrySet()) {
                if (tags.getKey() < 0) throw new IOException("Invalid tag UID");
                out.writeInt(tags.getKey()); out.writeInt(count(tags.getValue().size(), mThreshold));
                for (int tag : tags.getValue()) { if (tag == 0) throw new IOException("Invalid zero tag"); out.writeInt(tag); }
            }
            out.writeInt(count(state.stacked.size(), MAX_METADATA));
            for (Map.Entry<String, String> pair : state.stacked.entrySet()) {
                out.writeUTF(name(pair.getKey())); out.writeUTF(name(pair.getValue()));
            }
            out.writeInt(count(state.vpns.length, MAX_METADATA));
            for (UnderlyingNetworkInfo vpn : state.vpns) {
                if (vpn == null || vpn.getOwnerUid() < 0) throw new IOException("Invalid VPN owner");
                out.writeInt(vpn.getOwnerUid()); out.writeUTF(name(vpn.getInterface()));
                out.writeInt(count(vpn.getUnderlyingInterfaces().size(), MAX_METADATA));
                Set<String> seen = new HashSet<>();
                for (String iface : vpn.getUnderlyingInterfaces()) {
                    if (!seen.add(name(iface))) throw new IOException("Duplicate VPN interface"); out.writeUTF(iface);
                }
            }
            out.writeByte(state.removal==null?0:1);
            if(state.removal!=null){Removal r=state.removal;out.writeInt(r.uid);
                out.writeLong(r.generation);out.writeLong(r.epoch);out.writeLong(r.nonce);}
        }
        if (bytes.size() > MAX_BYTES) throw new IOException("Complete factory state exceeds journal capacity");
        return bytes.toByteArray();
    }
    private State decode(byte[] complete) throws IOException {
        if (complete.length > MAX_BYTES) throw new IOException("Oversized factory state");
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(complete))) {
            if(in.readInt()!=MAGIC)throw new IOException("Factory magic mismatch");
            int version=in.readInt();
            if ((version!=1&&version!=VERSION) || in.readBoolean() != mThrottle
                    || in.readInt() != mThreshold) throw new IOException("Factory schema/configuration mismatch");
            State state = new State(); state.raw = readStats(in); state.adjusted = readStats(in);
            int uids = count(in.readInt(), MAX_ROWS);
            for (int i = 0; i < uids; ++i) {
                int uid = in.readInt(), tags = count(in.readInt(), mThreshold);
                if (uid < 0 || state.tags.containsKey(uid)) throw new IOException("Duplicate/invalid tag UID");
                TreeSet<Integer> set = new TreeSet<>();
                for (int t = 0; t < tags; ++t) { int tag = in.readInt(); if (tag == 0 || !set.add(tag)) throw new IOException("Duplicate/zero tag"); }
                state.tags.put(uid, set);
            }
            int stacked = count(in.readInt(), MAX_METADATA);
            for (int i = 0; i < stacked; ++i) {
                if (state.stacked.put(name(in.readUTF()), name(in.readUTF())) != null) throw new IOException("Duplicate stacked interface");
            }
            int vpns = count(in.readInt(), MAX_METADATA); state.vpns = new UnderlyingNetworkInfo[vpns];
            for (int i = 0; i < vpns; ++i) {
                int uid = in.readInt(); String iface = name(in.readUTF());
                if (uid < 0) throw new IOException("Invalid VPN UID");
                int n = count(in.readInt(), MAX_METADATA); List<String> underlying = new ArrayList<>();
                for (int t = 0; t < n; ++t) { String item = name(in.readUTF()); if (underlying.contains(item)) throw new IOException("Duplicate VPN interface"); underlying.add(item); }
                state.vpns[i] = new UnderlyingNetworkInfo(uid, iface, underlying);
            }
            if(version>=2){int present=in.readUnsignedByte();if(present>1)throw new IOException("Invalid UID intent presence");
                if(present==1)state.removal=new Removal(in.readInt(),in.readLong(),in.readLong(),in.readLong());}
            if (in.available() != 0) throw new IOException("Trailing factory state");
            return state;
        } catch (RuntimeException bad) { throw new IOException("Malformed complete factory state", bad); }
    }
}
