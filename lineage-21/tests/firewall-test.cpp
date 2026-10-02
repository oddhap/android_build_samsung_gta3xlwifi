// SPDX-License-Identifier: Apache-2.0
#include "Gta3xlwifiLegacyFirewall.h"
#include "NetdConstants.h"
#include <cassert>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cerrno>
namespace android::net { std::mutex gBigNetdLock; }
struct Restore { IptablesTarget family; std::string rules; };
static std::vector<Restore> commands;
static int failAfter = -1;
int execIptablesRestore(IptablesTarget family, const std::string& rules) {
    commands.push_back({family, rules});
    if (failAfter == 0) { failAfter = -1; return 1; }
    if (failAfter > 0) --failAfter;
    return 0;
}
int main(int argc, char** argv) {
    using android::net::Gta3xlwifiLegacyFirewall;
    auto& fw = Gta3xlwifiLegacyFirewall::get();
    assert(fw.setUidRule(1, 10001, 1) == 0);
    assert(fw.enableChain(1, true) == 0);
    assert(!fw.isUidBlocked(10001, false));
    assert(fw.isUidBlocked(10002, false));
    failAfter = 1; // IPv4 succeeded; IPv6 fails once, rollback must restore both.
    assert(fw.replaceChain("fw_dozable", true, {10002}) == -EREMOTEIO);
    assert(!fw.isUidBlocked(10001, false));
    assert(fw.isUidBlocked(10002, false));
    assert(commands.back().rules.find("--uid-owner 10001 -j RETURN") != std::string::npos);
    assert(fw.replaceChain("fw_dozable", true, {10002}) == 0);
    assert(fw.isUidBlocked(10001, false));
    assert(!fw.isUidBlocked(10002, false));
    assert(fw.enableChain(1, false) == 0);
    assert(fw.setUidRule(2, 10002, 2) == 0);
    assert(fw.enableChain(2, true) == 0);
    assert(fw.isUidBlocked(10002, false));
    assert(!fw.isUidBlocked(10001, false));
    assert(fw.enableChain(2, false) == 0);
    assert(fw.replaceChain("gta3xlwifi_lockdown", true, {10001}) == 0);
    assert(fw.isUidBlocked(10001, false));
    assert(fw.setInterfaceRules("tun0", {10001}) == 0);
    assert(!fw.isUidBlocked(10001, false));
    assert(commands.back().rules.find("--uid-owner 10001 -o tun0 -j RETURN") != std::string::npos);
    assert(commands.back().rules.find("--uid-owner 10001 -j DROP") != std::string::npos);
    assert(fw.removeInterfaceRules({10001}) == 0);
    assert(fw.isUidBlocked(10001, false));
    assert(fw.replaceChain("gta3xlwifi_lockdown", true, {}) == 0);
    fw.setDataSaverState(true);
    assert(fw.isUidBlocked(10001, true));
    assert(!fw.isUidBlocked(10001, false));
    assert(fw.setMeteredUid(10001, true, true) == 0);
    assert(!fw.isUidBlocked(10001, true));
    failAfter = 0;
    assert(fw.setMeteredUid(10001, false, true) == -EREMOTEIO);
    assert(!fw.isUidBlocked(10001, true));
    assert(fw.setMeteredUid(10001, false, true) == 0);
    assert(fw.isUidBlocked(10001, true));
    fw.setPermissions(8, {10001});
    assert(fw.hasStatsPermission(110001));
    assert(fw.isUidBlocked(10001, false));
    fw.setPermissions(4, {10001});
    assert(!fw.hasStatsPermission(10001));
    assert(!fw.isUidBlocked(10001, false));
    const auto before = commands.size();
    assert(fw.setUidRule(99, 10001, 1) == -EINVAL);
    assert(fw.setUidRule(1, -1, 1) == -EINVAL);
    assert(fw.setInterfaceRules("tun0\n-j ACCEPT", {10001}) == -EINVAL);
    assert(fw.setIngressDiscard("not-an-ip", "tun0", true) == -EINVAL);
    assert(commands.size() == before);
    assert(fw.setIngressDiscard("2001:db8::1", "tun0", true) == 0);
    assert(fw.setIngressDiscard("192.0.2.1", "tun0", true) == 0);
    assert(fw.setIngressDiscard("192.0.2.1", "", false) == 0);
    if (argc == 2) {
        std::filesystem::create_directories(argv[1]);
        for (size_t i=0; i<commands.size(); ++i) {
            std::ofstream f(std::string(argv[1])+"/"+std::to_string(i)+"-"+std::to_string(commands[i].family)+".rules");
            f << commands[i].rules;
        }
    }
    std::cout << "Firewall policy, VPN lockdown, permissions, bad input and single-family rollback checks passed.\n";
}
