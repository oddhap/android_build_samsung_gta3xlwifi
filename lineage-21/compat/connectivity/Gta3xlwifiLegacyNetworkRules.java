// SPDX-License-Identifier: Apache-2.0
package com.android.server;

import static android.net.BpfNetMapsUtils.isFirewallAllowList;
import static android.net.ConnectivityManager.FIREWALL_RULE_ALLOW;
import static android.net.ConnectivityManager.FIREWALL_RULE_DENY;
import static android.system.OsConstants.EIO;

import android.net.INetd;
import com.android.internal.net.IOemNetd;
import java.net.InetAddress;
import android.os.RemoteException;
import android.os.ServiceSpecificException;
import android.os.SystemProperties;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Device-only iptables backend. Cache changes follow successful netd transactions. */
final class Gta3xlwifiLegacyNetworkRules {
    static boolean enabled() {
        return SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false);
    }
    private final INetd mNetd;
    private final IOemNetd mOem;
    private final Map<Integer, Set<Integer>> mRules = new HashMap<>();
    private final Set<Integer> mEnabled = new HashSet<>();
    private final Set<Integer> mNice = new HashSet<>(), mNaughty = new HashSet<>();
    private final Set<Integer> mLockdown = new HashSet<>();
    private final Map<Integer, String> mInterfaces = new HashMap<>();
    private boolean mDataSaver;
    interface NetdAction { void run() throws RemoteException; }
    private void call(NetdAction action) {
        try { action.run(); }
        catch (RemoteException e) {
            throw new ServiceSpecificException(EIO, "Legacy network backend unavailable: " + e);
        }
    }
    Gta3xlwifiLegacyNetworkRules(INetd netd) {
        if (netd == null) throw new IllegalArgumentException("Legacy networking requires netd");
        mNetd = netd;
        try { mOem = IOemNetd.Stub.asInterface(netd.getOemNetd()); }
        catch (RemoteException e) { throw new IllegalStateException("Missing OEM network backend", e); }
        if (mOem == null) throw new IllegalStateException("Missing OEM network backend");
    }
    private static String name(int chain) {
        switch (chain) {
            case 1: return "fw_dozable";
            case 2: return "fw_standby";
            case 3: return "fw_powersave";
            case 4: return "fw_restricted";
            case 5: return "fw_low_power_standby";
            case 6: return "fw_background";
            case 7: return "fw_oem_deny_1";
            case 8: return "fw_oem_deny_2";
            case 9: return "fw_oem_deny_3";
            default: throw new IllegalArgumentException("Invalid firewall chain: " + chain);
        }
    }
    synchronized void setChildChain(int chain, boolean enable) {
        name(chain);
        call(() -> mNetd.firewallEnableChildChain(chain, enable));
        if (enable) mEnabled.add(chain); else mEnabled.remove(chain);
    }
    synchronized boolean isChainEnabled(int chain) { name(chain); return mEnabled.contains(chain); }
    synchronized void setUidRule(int chain, int uid, int rule) {
        name(chain);
        call(() -> mNetd.firewallSetUidRule(chain, uid, rule));
        Set<Integer> uids = mRules.computeIfAbsent(chain, ignored -> new HashSet<>());
        final boolean add = (rule == FIREWALL_RULE_ALLOW && isFirewallAllowList(chain))
                || (rule == FIREWALL_RULE_DENY && !isFirewallAllowList(chain));
        if (add) uids.add(uid); else uids.remove(uid);
    }
    synchronized int getUidRule(int chain, int uid) {
        name(chain);
        boolean match = mRules.getOrDefault(chain, Set.of()).contains(uid);
        return match == isFirewallAllowList(chain) ? FIREWALL_RULE_ALLOW : FIREWALL_RULE_DENY;
    }
    synchronized Set<Integer> getUids(int chain) {
        name(chain); return new HashSet<>(mRules.getOrDefault(chain, Set.of()));
    }
    synchronized void replaceUidChain(int chain, int[] uids) {
        String chainName = name(chain);
        call(() -> {
            if (!mNetd.firewallReplaceUidChain(chainName, isFirewallAllowList(chain), uids))
                throw new ServiceSpecificException(EIO, "Legacy chain replacement failed");
        });
        Set<Integer> next = new HashSet<>();
        for (int uid : uids) next.add(uid);
        mRules.put(chain, next);
    }
    synchronized void meteredUid(int uid, boolean nice, boolean add) {
        call(() -> {
            if (nice) {
                if (add) mNetd.bandwidthAddNiceApp(uid); else mNetd.bandwidthRemoveNiceApp(uid);
            } else {
                if (add) mNetd.bandwidthAddNaughtyApp(uid); else mNetd.bandwidthRemoveNaughtyApp(uid);
            }
        });
        Set<Integer> values = nice ? mNice : mNaughty;
        if (add) values.add(uid); else values.remove(uid);
    }
    synchronized void setDataSaver(boolean enable) {
        call(() -> {
            if (!mNetd.bandwidthEnableDataSaver(enable))
                throw new ServiceSpecificException(EIO, "Legacy data saver update failed");
        });
        mDataSaver = enable;
    }
    synchronized void addInterfaceRules(String iface, int[] uids) {
        if (iface == null) { removeInterfaceRules(uids); return; }
        call(() -> mNetd.firewallAddUidInterfaceRules(iface, uids));
        for (int uid : uids) mInterfaces.put(uid, iface);
    }
    synchronized void removeInterfaceRules(int[] uids) {
        call(() -> mNetd.firewallRemoveUidInterfaceRules(uids));
        for (int uid : uids) mInterfaces.remove(uid);
    }
    synchronized void updateLockdown(int uid, boolean add) {
        Set<Integer> next = new HashSet<>(mLockdown);
        if (add) next.add(uid); else next.remove(uid);
        int[] values = next.stream().mapToInt(Integer::intValue).toArray();
        call(() -> {
            if (!mNetd.firewallReplaceUidChain("gta3xlwifi_lockdown", true, values))
                throw new ServiceSpecificException(EIO, "Legacy VPN lockdown update failed");
        });
        mLockdown.clear(); mLockdown.addAll(next);
    }
    synchronized void setIngressDiscard(InetAddress address, String iface, boolean add) {
        String value = address.getHostAddress().split("%", 2)[0];
        call(() -> mOem.gta3xlwifiSetIngressDiscardRule(value, iface == null ? "" : iface, add));
    }
    synchronized void setNetPermForUids(int permissions, int[] uids) {
        call(() -> mNetd.trafficSetNetPermForUids(permissions, uids));
    }
    synchronized boolean isUidBlocked(int uid, boolean metered) {
        if (uid >= 10000) {
            for (int chain : mEnabled)
                if (getUidRule(chain, uid) == FIREWALL_RULE_DENY) return true;
        }
        if (mLockdown.contains(uid) && !mInterfaces.containsKey(uid)) return true;
        if (!metered) return false;
        if (mNaughty.contains(uid)) return true;
        return !mNice.contains(uid) && mDataSaver;
    }
}
