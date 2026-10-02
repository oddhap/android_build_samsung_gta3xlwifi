// SPDX-License-Identifier: Apache-2.0
#include "Gta3xlwifiLegacyStats.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string>
#include <iostream>
static std::string detail, dev;
static bool missing = false;
FILE* gta3xlwifiTestOpen(const char* name, const char*) {
    if (missing) { errno=ENOENT; return nullptr; }
    const auto& data = std::string(name).find("iface_stat_fmt") != std::string::npos ? dev : detail;
    FILE* file=tmpfile(); assert(file);
    assert(fwrite(data.data(),1,data.size(),file)==data.size()); rewind(file); return file;
}
namespace android::bpf {
// A dependency stub: the production parser's aggregation is exercised by the
// upstream libnetworkstats tests; here the rows are unique and only sorted.
void groupNetworkStats(std::vector<stats_line>& lines) {
    std::sort(lines.begin(),lines.end(),[](const auto& a,const auto& b) {
        if (a.uid!=b.uid) return a.uid<b.uid;
        if (a.set!=b.set) return a.set<b.set;
        return a.tag<b.tag;
    });
}
}
int main() {
    using namespace android::bpf;
    // Real Samsung qtaguid column order. Tagged records are also included in
    // UID tag-zero totals, so tagged rows must not be counted twice.
    detail="idx iface acct_tag_hex uid_tag_int cnt_set rx_bytes rx_packets tx_bytes tx_packets extra\n"
           "2 wlan0 0x0 10001 0 300 3 400 4 1 2 3\n"
           "3 wlan0 0x0 10001 1 200 2 100 1 1 2 3\n"
           "4 wlan0 0x123400000000 10001 0 50 1 60 1 1 2 3\n"
           "5 wlan0 0x0 10002 0 800 8 900 9 1 2 3\n";
    dev="ifname total_skb_rx_bytes total_skb_rx_packets total_skb_tx_bytes total_skb_tx_packets extra\n"
        "wlan0 1000 10 2000 20 1 2 3\nlo 100 1 100 1 1 2 3\n";
    StatsValue counters;
    assert(gta3xlwifiLegacyUidStats(10001,&counters)==0);
    assert(counters.rxBytes==500 && counters.txBytes==500);
    assert(counters.rxPackets==5 && counters.txPackets==5);
    std::vector<stats_line> rows;
    assert(gta3xlwifiLegacyDetail(&rows)==0 && rows.size()==4);
    assert(rows[1].tag==0x1234 && rows[1].rxBytes==50);
    assert(gta3xlwifiLegacyIfaceStats("wlan0",&counters)==0);
    assert(counters.rxBytes==1000 && counters.txBytes==2000);
    assert(gta3xlwifiLegacyIfaceStats(nullptr,&counters)==0);
    assert(counters.rxBytes==1100 && counters.txBytes==2100);
    // Polling twice must produce the same cumulative totals.
    assert(gta3xlwifiLegacyUidStats(10001,&counters)==0 && counters.rxBytes==500);
    assert(gta3xlwifiLegacyUidStats(10001,&counters)==0 && counters.rxBytes==500);
    missing=true;
    assert(gta3xlwifiLegacyUidStats(10001,&counters)==-ENOENT);
    missing=false; detail="malformed kernel record\n"; rows.clear();
    assert(gta3xlwifiLegacyDetail(&rows)==-EINVAL);
    dev="malformed interface record\n"; rows.clear();
    assert(gta3xlwifiLegacyDev(&rows)==-EINVAL);
    std::cout << "qtaguid column parsing, tag separation, foreground sets, interface totals and error checks passed.\n";
}
