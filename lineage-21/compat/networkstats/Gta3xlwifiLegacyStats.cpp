// SPDX-License-Identifier: Apache-2.0
#include <cinttypes>
#include "Gta3xlwifiLegacyStats.h"
#include <android-base/properties.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
namespace android::bpf {
bool gta3xlwifiLegacyStatsEnabled() {
    return android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false);
}
int gta3xlwifiLegacyDetail(std::vector<stats_line>* lines) {
    FILE* f = fopen("/proc/net/xt_qtaguid/stats", "re");
    if (!f) return -errno;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "idx ", 4)) continue;
        stats_line entry = {};
        uint32_t idx, uid, set; uint64_t tag, rxBytes, rxPackets, txBytes, txPackets;
        int count = sscanf(line, "%" SCNu32 " %31s 0x%" SCNx64 " %" SCNu32 " %" SCNu32
                " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
                &idx, entry.iface, &tag, &uid, &set, &rxBytes, &rxPackets, &txBytes, &txPackets);
        if (count != 9) { fclose(f); return -EINVAL; }
        entry.uid = uid; entry.set = set; entry.tag = tag >> 32;
        entry.rxBytes = rxBytes; entry.rxPackets = rxPackets;
        entry.txBytes = txBytes; entry.txPackets = txPackets;
        lines->push_back(entry);
    }
    int err = ferror(f) ? -EIO : 0;
    fclose(f);
    if (!err) groupNetworkStats(*lines);
    return err;
}
int gta3xlwifiLegacyUidStats(uid_t uid, StatsValue* stats) {
    *stats = {};
    std::vector<stats_line> lines;
    int res = gta3xlwifiLegacyDetail(&lines); if (res) return res;
    for (const auto& line : lines) {
        if (line.uid != uid || line.tag != 0) continue;
        stats->rxBytes += line.rxBytes; stats->rxPackets += line.rxPackets;
        stats->txBytes += line.txBytes; stats->txPackets += line.txPackets;
    }
    return 0;
}
int gta3xlwifiLegacyDev(std::vector<stats_line>* lines) {
    FILE* f = fopen("/proc/net/xt_qtaguid/iface_stat_fmt", "re");
    if (!f) return -errno;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), f)) {
        stats_line entry = {};
        uint64_t rxBytes, rxPackets, txBytes, txPackets;
        int count = sscanf(buffer, "%31s %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
                           entry.iface, &rxBytes, &rxPackets, &txBytes, &txPackets);
        if (count != 5) {
            if (!strncmp(buffer, "ifname ", 7)) continue;
            fclose(f); return -EINVAL;
        }
        entry.uid = UID_ALL; entry.set = SET_ALL; entry.tag = TAG_NONE;
        entry.rxBytes = rxBytes; entry.rxPackets = rxPackets;
        entry.txBytes = txBytes; entry.txPackets = txPackets;
        lines->push_back(entry);
    }
    int err = ferror(f) ? -EIO : 0;
    fclose(f);
    if (!err) groupNetworkStats(*lines);
    return err;
}
int gta3xlwifiLegacyIfaceStats(const char* iface, StatsValue* stats) {
    *stats = {};
    std::vector<stats_line> lines;
    int res = gta3xlwifiLegacyDev(&lines); if (res) return res;
    for (const auto& line : lines) {
        if (iface && strcmp(iface, line.iface)) continue;
        stats->rxBytes += line.rxBytes; stats->rxPackets += line.rxPackets;
        stats->txBytes += line.txBytes; stats->txPackets += line.txPackets;
    }
    return 0;
}
}
