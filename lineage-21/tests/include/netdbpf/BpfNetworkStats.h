#pragma once
#include <cstdint>
#include <vector>
#include <sys/types.h>
namespace android::bpf {
constexpr int UID_ALL=-1, SET_ALL=-1, TAG_NONE=0;
struct StatsValue { uint64_t rxPackets, rxBytes, txPackets, txBytes; };
struct stats_line {
    char iface[32]; uint32_t uid, set, tag;
    int64_t rxBytes, rxPackets, txBytes, txPackets;
};
void groupNetworkStats(std::vector<stats_line>& lines);
}
