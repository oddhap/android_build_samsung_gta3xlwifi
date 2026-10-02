// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "netdbpf/BpfNetworkStats.h"
namespace android::bpf {
bool gta3xlwifiLegacyStatsEnabled();
int gta3xlwifiLegacyUidStats(uid_t uid, StatsValue* stats);
int gta3xlwifiLegacyIfaceStats(const char* iface, StatsValue* stats);
int gta3xlwifiLegacyDetail(std::vector<stats_line>* lines);
int gta3xlwifiLegacyDev(std::vector<stats_line>* lines);
}
