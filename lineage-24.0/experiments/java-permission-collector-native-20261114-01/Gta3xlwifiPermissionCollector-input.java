/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server;

import android.os.Process;
import android.util.SparseIntArray;
import com.android.modules.utils.build.SdkLevel;
import com.android.server.permission.PermissionBpfMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Ordered raw permission consumer, not a networking readiness indicator. The
 * caller supplies its sole policy-cache lock and an actual owner publication/
 * invalidation sink. No PackageManager/UserManager call is made under this lock.
 * @hide
 */
public final class Gta3xlwifiPermissionCollector implements PermissionBpfMap {
    private static final int USER_RANGE = 100000;
    private static final int RAW_MASK = 1023;
    private static final int MAX_ENTRIES = 65536;
    private final Object mLock;
    private final Sink mSink;
    private Data mData;
    private Snapshot mSnapshot;

    /** Backend must use the SAME lock for all other policy state and publication. */
    public interface Sink {
        void accept(Snapshot completePermissions);
        /** Withdraw actual owner publication/HOLD; must not register observers here. */
        void invalidate(Throwable cause);
    }

    /** Immutable raw input; INTERNET-only remains an observed raw4, not absence. */
    public static final class Snapshot {
        private final int[] mUsers;
        private final int[] mKnown;
        private final int[] mRaw;
        private Snapshot(Data data) {
            mUsers = data.users.stream().mapToInt(Integer::intValue).toArray();
            mKnown = data.known.stream().mapToInt(Integer::intValue).toArray();
            mRaw = new int[data.raw.size() * 2];
            int i = 0;
            for (Map.Entry<Integer, Integer> entry : data.raw.entrySet()) {
                mRaw[i++] = entry.getKey();
                mRaw[i++] = entry.getValue();
            }
        }
        public int[] users() { return mUsers.clone(); }
        public int[] knownUids() { return mKnown.clone(); }
        public int[] rawPermissionWords() { return mRaw.clone(); }
    }

    private static final class Data {
        final TreeSet<Integer> users = new TreeSet<>();
        final TreeSet<Integer> known = new TreeSet<>();
        final TreeMap<Integer, Integer> raw = new TreeMap<>();
        Data() {}
        Data(Data source) {
            users.addAll(source.users);
            known.addAll(source.known);
            raw.putAll(source.raw);
        }
    }

    public Gta3xlwifiPermissionCollector(Object sharedPolicyLock, Sink sink) {
        mLock = Objects.requireNonNull(sharedPolicyLock);
        mSink = Objects.requireNonNull(sink);
    }

    private static boolean hasSdkSandbox(int uid) {
        return SdkLevel.isAtLeastT() && Process.isApplicationUid(uid);
    }

    private static void requireUid(Data data, int uid) {
        if (uid < 0 || !data.users.contains(uid / USER_RANGE)) {
            throw new IllegalArgumentException("UID outside complete user frame: " + uid);
        }
    }

    private static void known(Data data, int uid) {
        requireUid(data, uid);
        data.known.add(uid);
        if (hasSdkSandbox(uid)) data.known.add(Process.toSdkSandboxUid(uid));
    }

    private static void observed(TreeMap<Integer, Integer> rows, int uid, int raw) {
        Integer previous = rows.putIfAbsent(uid, raw);
        if (previous != null && previous != raw) {
            throw new IllegalArgumentException("Conflicting SDK permission projection: " + uid);
        }
    }

    private static void mergeRaw(Data data, SparseIntArray values) {
        Objects.requireNonNull(values);
        if (values.size() > MAX_ENTRIES) throw new IllegalArgumentException("Oversized raw frame");
        // Validate the entire callback projection independently before replacing
        // any old rows. A live revocation must replace, not conflict with, a grant.
        TreeMap<Integer, Integer> projected = new TreeMap<>();
        for (int i = 0; i < values.size(); ++i) {
            int uid = values.keyAt(i);
            int raw = values.valueAt(i);
            requireUid(data, uid);
            if ((raw & ~RAW_MASK) != 0) {
                throw new IllegalArgumentException("Unknown raw permission bits");
            }
            observed(projected, uid, raw);
            if (hasSdkSandbox(uid)) observed(projected, Process.toSdkSandboxUid(uid), raw);
        }
        data.raw.putAll(projected);
    }

    private static void validate(Data data) {
        if (!data.users.contains(0)) throw new IllegalArgumentException("Missing system user");
        if (data.users.size() > MAX_ENTRIES || data.known.size() > MAX_ENTRIES
                || data.raw.size() > MAX_ENTRIES) {
            throw new IllegalArgumentException("Permission frame exceeds native bounds");
        }
        for (int user : data.users) {
            if (user < 0 || user > (Integer.MAX_VALUE - 1000) / USER_RANGE) {
                throw new IllegalArgumentException("Invalid user");
            }
            for (int appId : new int[] {0, 1000}) {
                Integer raw = data.raw.get(user * USER_RANGE + appId);
                if (raw == null || raw != RAW_MASK) {
                    throw new IllegalArgumentException("Missing observed full core permissions");
                }
            }
        }
    }

    private void accept(Data next) {
        validate(next);
        Snapshot snapshot = new Snapshot(next);
        mSink.accept(snapshot); // May buffer while OTHER policy inputs remain held.
        mData = next;
        mSnapshot = snapshot; // Permission input only, never global Ready.
    }

    private void invalidated(Throwable failure) {
        mData = null;
        mSnapshot = null;
        try {
            mSink.invalidate(failure);
        } catch (RuntimeException | Error stopFailure) {
            failure.addSuppressed(stopFailure);
        }
    }

    @Override
    public void setInitialUidPermissions(int[] userIds, int[] knownPackageUids,
            SparseIntArray rawPermissionBits) {
        synchronized (mLock) {
            try {
                Objects.requireNonNull(userIds);
                Objects.requireNonNull(knownPackageUids);
                if (userIds.length > MAX_ENTRIES || knownPackageUids.length > MAX_ENTRIES) {
                    throw new IllegalArgumentException("Oversized identity frame");
                }
                Data next = new Data();
                for (int user : userIds) {
                    if (user < 0 || user > (Integer.MAX_VALUE - 1000) / USER_RANGE
                            || !next.users.add(user)) {
                        throw new IllegalArgumentException("Invalid or duplicate user");
                    }
                }
                for (int uid : Objects.requireNonNull(knownPackageUids)) known(next, uid);
                mergeRaw(next, rawPermissionBits);
                accept(next);
            } catch (RuntimeException | Error failure) {
                invalidated(failure);
                throw failure;
            }
        }
    }

    @Override
    public void setUidsPermissionBits(SparseIntArray rawPermissionBits) {
        synchronized (mLock) {
            try {
                if (mData == null) throw new IllegalStateException("Complete metadata required");
                Data next = new Data(mData);
                mergeRaw(next, rawPermissionBits);
                accept(next);
            } catch (RuntimeException | Error failure) {
                invalidated(failure);
                throw failure;
            }
        }
    }

    @Override
    public void removeAppId(int appId) {
        synchronized (mLock) {
            try {
                if (mData == null) throw new IllegalStateException("Complete metadata required");
                if (appId < 0 || appId >= USER_RANGE) {
                    throw new IllegalArgumentException("Invalid appId");
                }
                Data next = new Data(mData);
                int sandbox = hasSdkSandbox(appId) ? Process.toSdkSandboxUid(appId) : -1;
                next.known.removeIf(uid -> uid % USER_RANGE == appId
                        || uid % USER_RANGE == sandbox);
                next.raw.keySet().removeIf(uid -> uid % USER_RANGE == appId
                        || uid % USER_RANGE == sandbox);
                accept(next);
            } catch (RuntimeException | Error failure) {
                invalidated(failure);
                throw failure;
            }
        }
    }

    @Override
    public void removeUser(int userId) {
        synchronized (mLock) {
            try {
                if (mData == null) throw new IllegalStateException("Complete metadata required");
                if (userId < 0) throw new IllegalArgumentException("Invalid user");
                Data next = new Data(mData);
                next.users.remove(userId);
                next.known.removeIf(uid -> uid / USER_RANGE == userId);
                next.raw.keySet().removeIf(uid -> uid / USER_RANGE == userId);
                accept(next);
            } catch (RuntimeException | Error failure) {
                invalidated(failure);
                throw failure;
            }
        }
    }

    public Snapshot snapshot() {
        synchronized (mLock) {
            if (mSnapshot == null) throw new IllegalStateException("Complete metadata required");
            return mSnapshot;
        }
    }
}
