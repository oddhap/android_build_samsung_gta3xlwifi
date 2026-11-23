/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server;

import android.net.NetworkStats;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/** Nonconsuming real packet counters for existing TrafficStats service APIs. @hide */
public final class Gta3xlwifiTrafficStats {
    private final Gta3xlwifiStatsAccess mStats;
    public Gta3xlwifiTrafficStats(Gta3xlwifiStatsAccess stats) {
        mStats = Objects.requireNonNull(stats);
    }
    /** A complete, lossless table proves absent UID counters are zero, as A17 ENOENT does. */
    public NetworkStats.Entry uid(int uid) throws IOException {
        if (uid < 0) throw new IOException("Invalid UID");
        Gta3xlwifiStatsAccess.Snapshot apps = mStats.readApps(); apps.requireLossless();
        NetworkStats.Entry out = empty(null, uid);
        for (int i = 0; i < apps.count; ++i) {
            long[] row = apps.row(i);
            if (row[0] == uid) { add(out, row); break; }
        }
        return out;
    }
    /** null is the same real all-interface wildcard as bpfGetIfaceStatsInternal. */
    public NetworkStats.Entry iface(String iface) throws IOException {
        Gta3xlwifiStatsAccess.Snapshot interfaces = mStats.readInterfaces();
        interfaces.requireLossless();
        Map<Long, String> names = null;
        if (iface != null) {
            Gta3xlwifiStatsAccess.Snapshot history = mStats.readInterfaceNames();
            history.requireLossless(); names = new HashMap<>();
            for (int i = 0; i < history.count; ++i) {
                names.put(history.row(i)[0], history.interfaceName(i));
            }
        }
        NetworkStats.Entry out = empty(iface, NetworkStats.UID_ALL);
        long unknown = 0;
        for (int i = 0; i < interfaces.count; ++i) {
            long[] row = interfaces.row(i);
            if (iface != null) {
                String actual = names.get(row[0]);
                if (actual == null) {
                    // As A17 bpfGetIfaceStatsInternal: an unnamed ifindex never matches.
                    unknown = Gta3xlwifiStatsConsumer.noteUnknownIface(unknown, row[0], row[2], row[4]);
                    continue;
                }
                if (!iface.equals(actual)) continue;
            }
            add(out, row);
        }
        return out;
    }
    private static NetworkStats.Entry empty(String iface, int uid) {
        return new NetworkStats.Entry(iface, uid, NetworkStats.SET_ALL, 0,
                0, 0, 0, 0, 0, 0, 0, 0);
    }
    private static void add(NetworkStats.Entry entry, long[] row) throws IOException {
        for (int i = 1; i < 5; ++i) {
            if (row[i] < 0) throw new IOException("Unsigned TrafficStats counter exceeds signed range");
        }
        try {
            entry.rxPackets = Math.addExact(entry.rxPackets, row[1]);
            entry.rxBytes = Math.addExact(entry.rxBytes, row[2]);
            entry.txPackets = Math.addExact(entry.txPackets, row[3]);
            entry.txBytes = Math.addExact(entry.txBytes, row[4]);
        } catch (ArithmeticException overflow) { throw new IOException("TrafficStats sum overflow", overflow); }
    }
}
