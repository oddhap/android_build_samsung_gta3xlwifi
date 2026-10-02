// SPDX-License-Identifier: Apache-2.0
#include "Gta3xlwifiLegacyFirewall.h"
#include "FirewallController.h"
#include "NetdConstants.h"
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <cerrno>
#include <arpa/inet.h>
#include <climits>
using android::base::StringAppendF;
namespace android::net {
bool Gta3xlwifiLegacyFirewall::enabled() {
    return android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false);
}
Gta3xlwifiLegacyFirewall& Gta3xlwifiLegacyFirewall::get() {
    static Gta3xlwifiLegacyFirewall instance;
    return instance;
}
const char* Gta3xlwifiLegacyFirewall::name(int chain) {
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
        default: return nullptr;
    }
}
bool Gta3xlwifiLegacyFirewall::allowlist(int chain) {
    return chain == 1 || chain == 3 || chain == 4 || chain == 5 || chain == 6;
}
static int run(const std::string& commands) {
    return execIptablesRestore(V4V6, commands) == 0 ? 0 : -EREMOTEIO;
}
int Gta3xlwifiLegacyFirewall::applyChain(int chain, const Chain& value) {
    const char* n = name(chain);
    if (!n) return -EINVAL;
    // Android exempts loopback from these policies; neighbour discovery must
    // remain usable on allowlist chains.
    for (IptablesTarget family : {V4, V6}) {
        std::string cmd = "*filter\n";
        StringAppendF(&cmd, ":%s -\n", n);
        StringAppendF(&cmd, "-A %s -i lo -j RETURN\n-A %s -o lo -j RETURN\n", n, n);
        StringAppendF(&cmd, "-A %s -p tcp --tcp-flags RST RST -j RETURN\n", n);
        if (allowlist(chain)) cmd += FirewallController::makeCriticalCommands(family, n);
        if (allowlist(chain)) {
            // Match Android's FIRST_APPLICATION_UID exemption and packets with
            // no owning socket. Samsung qtaguid supplies owner matching at INPUT.
            StringAppendF(&cmd, "-A %s -m owner --uid-owner 0-9999 -j RETURN\n", n);
            StringAppendF(&cmd, "-A %s -m owner ! --uid-owner 0-%u -j RETURN\n", n, UINT_MAX - 1);
            StringAppendF(&cmd, "-A %s -p esp -j RETURN\n", n);
        }
        for (int uid : value.uids)
            StringAppendF(&cmd, "-A %s -m owner --uid-owner %d -j %s\n", n, uid,
                          allowlist(chain) ? "RETURN" : "DROP");
        if (allowlist(chain)) StringAppendF(&cmd, "-A %s -j DROP\n", n);
        cmd += "COMMIT\n";
        if (execIptablesRestore(family, cmd)) return -EREMOTEIO;
    }
    return 0;
}
int Gta3xlwifiLegacyFirewall::init() {
    if (mInitialized) return 0;
    for (int chain = 1; chain <= 9; ++chain) {
        int res = applyChain(chain, {});
        if (res) return res;
    }
    std::string cmd = "*filter\n:gta3xlwifi_iif -\n"
                      ":gta3xlwifi_ingress -\n:gta3xlwifi_lockdown_output -\n"
                      ":gta3xlwifi_INPUT -\n:gta3xlwifi_OUTPUT -\n"
                      "-A INPUT -j gta3xlwifi_INPUT\n"
                      "-A OUTPUT -j gta3xlwifi_OUTPUT\nCOMMIT\n";
    int res = run(cmd);
    if (!res) res = applyAttachments(mChains);
    if (res) return res;
    mInitialized = true;
    return 0;
}
int Gta3xlwifiLegacyFirewall::setUidRule(int chain, int uid, int rule) {
    if (!name(chain) || uid < 0 || (rule != 0 && rule != 1 && rule != 2)) return -EINVAL;
    int res = init(); if (res) return res;
    Chain next = mChains[chain];
    if ((rule == 1 && allowlist(chain)) || (rule == 2 && !allowlist(chain))) next.uids.insert(uid);
    else next.uids.erase(uid);
    res = applyChain(chain, next);
    if (res) { applyChain(chain, mChains[chain]); return res; }
    mChains[chain] = std::move(next);
    return 0;
}
int Gta3xlwifiLegacyFirewall::applyAttachments(const std::map<int, Chain>& chains) {
    std::string cmd = "*filter\n:gta3xlwifi_INPUT -\n:gta3xlwifi_OUTPUT -\n"
                      "-A gta3xlwifi_INPUT -j gta3xlwifi_ingress\n"
                      "-A gta3xlwifi_INPUT -j gta3xlwifi_iif\n"
                      "-A gta3xlwifi_OUTPUT -j gta3xlwifi_lockdown_output\n";
    for (const auto& [chain, state] : chains) {
        if (!state.enabled) continue;
        StringAppendF(&cmd, "-A gta3xlwifi_INPUT -j %s\n-A gta3xlwifi_OUTPUT -j %s\n",
                      name(chain), name(chain));
    }
    cmd += "COMMIT\n";
    return run(cmd);
}
int Gta3xlwifiLegacyFirewall::enableChain(int chain, bool enable) {
    if (!name(chain)) return -EINVAL;
    int res = init(); if (res) return res;
    if (mChains[chain].enabled == enable) return 0;
    auto next = mChains; next[chain].enabled = enable;
    res = applyAttachments(next);
    if (res) { applyAttachments(mChains); return res; }
    mChains = std::move(next);
    return 0;
}
int Gta3xlwifiLegacyFirewall::replaceChain(const std::string& n, bool list,
                                          const std::vector<int32_t>& uids) {
    if (n == "gta3xlwifi_lockdown") {
        if (!list) return -EINVAL;
        for (int uid : uids) if (uid < 0) return -EINVAL;
        int res = init(); if (res) return res;
        auto old = mLockdown;
        mLockdown = {uids.begin(), uids.end()};
        res = applyInterfaces(mInterfaces);
        if (res) { mLockdown = std::move(old); applyInterfaces(mInterfaces); }
        return res;
    }
    int chain = 0;
    for (int c = 1; c <= 9; ++c) if (n == name(c)) chain = c;
    if (!chain || allowlist(chain) != list) return -EINVAL;
    for (int uid : uids) if (uid < 0) return -EINVAL;
    int res = init(); if (res) return res;
    Chain next = mChains[chain]; next.uids = {uids.begin(), uids.end()};
    res = applyChain(chain, next);
    if (res) { applyChain(chain, mChains[chain]); return res; }
    mChains[chain] = std::move(next);
    return 0;
}
int Gta3xlwifiLegacyFirewall::setMeteredUid(int uid, bool nice, bool add) {
    if (uid < 0) return -EINVAL;
    auto& values = nice ? mNice : mNaughty;
    const bool exists = values.count(uid);
    if (exists == add) return 0;
    std::string cmd = "*filter\n";
    StringAppendF(&cmd, "%s %s -m owner --uid-owner %d -j %s\nCOMMIT\n",
                  add ? "-I" : "-D", nice ? "bw_happy_box" : "bw_penalty_box", uid,
                  nice ? "RETURN" : "REJECT");
    int res = run(cmd);
    if (!res) { if (add) values.insert(uid); else values.erase(uid); }
    return res;
}
int Gta3xlwifiLegacyFirewall::applyInterfaces(const std::map<int, std::string>& values) {
    std::string cmd = "*filter\n:gta3xlwifi_iif -\n:gta3xlwifi_lockdown_output -\n"
                      "-A gta3xlwifi_iif -i lo -j RETURN\n"
                      "-A gta3xlwifi_lockdown_output -o lo -j RETURN\n";
    auto all = mLockdown;
    for (const auto& [uid, iface] : values) all.insert(uid);
    for (int uid : all) {
        auto it = values.find(uid);
        if (it != values.end()) {
            StringAppendF(&cmd, "-A gta3xlwifi_iif -m owner --uid-owner %d -i %s -j RETURN\n",
                          uid, it->second.c_str());
            if (mLockdown.count(uid))
                StringAppendF(&cmd, "-A gta3xlwifi_lockdown_output -m owner --uid-owner %d -o %s -j RETURN\n",
                              uid, it->second.c_str());
        }
        StringAppendF(&cmd, "-A gta3xlwifi_iif -m owner --uid-owner %d -j DROP\n", uid);
        if (mLockdown.count(uid))
            StringAppendF(&cmd, "-A gta3xlwifi_lockdown_output -m owner --uid-owner %d -j DROP\n", uid);
    }
    cmd += "COMMIT\n";
    return run(cmd);
}
int Gta3xlwifiLegacyFirewall::setInterfaceRules(const std::string& iface,
                                               const std::vector<int32_t>& uids) {
    if (!isIfaceName(iface)) return -EINVAL;
    int res = init(); if (res) return res;
    auto next = mInterfaces;
    for (int uid : uids) { if (uid < 0) return -EINVAL; next[uid] = iface; }
    res = applyInterfaces(next);
    if (res) { applyInterfaces(mInterfaces); return res; }
    mInterfaces = std::move(next);
    return 0;
}
int Gta3xlwifiLegacyFirewall::removeInterfaceRules(const std::vector<int32_t>& uids) {
    int res = init(); if (res) return res;
    auto next = mInterfaces;
    for (int uid : uids) next.erase(uid);
    res = applyInterfaces(next);
    if (res) { applyInterfaces(mInterfaces); return res; }
    mInterfaces = std::move(next);
    return 0;
}
int Gta3xlwifiLegacyFirewall::applyIngress(const std::map<std::string, std::string>& values) {
    for (IptablesTarget family : {V4, V6}) {
        std::string cmd = "*filter\n:gta3xlwifi_ingress -\n"
                          "-A gta3xlwifi_ingress -i lo -j RETURN\n";
        for (const auto& [address, iface] : values) {
            const bool v6 = address.find(':') != std::string::npos;
            if (v6 != (family == V6)) continue;
            StringAppendF(&cmd, "-A gta3xlwifi_ingress -d %s ! -i %s -j DROP\n",
                          address.c_str(), iface.c_str());
        }
        cmd += "COMMIT\n";
        if (execIptablesRestore(family, cmd)) return -EREMOTEIO;
    }
    return 0;
}
int Gta3xlwifiLegacyFirewall::setIngressDiscard(const std::string& address,
                                                const std::string& iface, bool add) {
    unsigned char bytes[16]; char canonical[INET6_ADDRSTRLEN];
    const int family = address.find(':') != std::string::npos ? AF_INET6 : AF_INET;
    if (inet_pton(family, address.c_str(), bytes) != 1 ||
        !inet_ntop(family, bytes, canonical, sizeof(canonical)) ||
        (add && !isIfaceName(iface))) return -EINVAL;
    int res = init(); if (res) return res;
    auto next = mIngress;
    if (add) next[canonical] = iface; else next.erase(canonical);
    res = applyIngress(next);
    if (res) { applyIngress(mIngress); return res; }
    mIngress = std::move(next);
    return 0;
}
void Gta3xlwifiLegacyFirewall::setPermissions(int permissions, const std::vector<int32_t>& uids) {
    for (int uid : uids) {
        if (permissions == INetd::PERMISSION_UNINSTALLED) mPermissions.erase(uid % 100000);
        else mPermissions[uid % 100000] = permissions;
    }
}
bool Gta3xlwifiLegacyFirewall::hasStatsPermission(int uid) const {
    if (uid == 0 || uid == 1000 || uid == 1051) return true;
    auto it = mPermissions.find(uid % 100000);
    return it != mPermissions.end() && (it->second & INetd::PERMISSION_UPDATE_DEVICE_STATS);
}
bool Gta3xlwifiLegacyFirewall::isUidBlocked(int uid, bool metered) const {
    if (uid < 10000) return false;
    auto permission = mPermissions.find(uid % 100000);
    if (permission != mPermissions.end() && !(permission->second & INetd::PERMISSION_INTERNET))
        return true;
    for (const auto& [chain, state] : mChains) {
        if (state.enabled && (state.uids.count(uid) != allowlist(chain))) return true;
    }
    if (mLockdown.count(uid) && !mInterfaces.count(uid)) return true;
    if (!metered) return false;
    if (mNaughty.count(uid)) return true;
    return !mNice.count(uid) && mDataSaver;
}

}

// Resolver and socket tagging run inside the netd process. These read-only
// callbacks preserve policy and permission checks without a BPF map.
extern "C" __attribute__((visibility("default")))
bool gta3xlwifi_legacy_is_uid_networking_blocked(unsigned uid, bool metered) {
    std::lock_guard guard(android::net::gBigNetdLock);
    return android::net::Gta3xlwifiLegacyFirewall::get().isUidBlocked(uid, metered);
}
extern "C" __attribute__((visibility("default")))
bool gta3xlwifi_legacy_has_stats_permission(unsigned uid) {
    std::lock_guard guard(android::net::gBigNetdLock);
    return android::net::Gta3xlwifiLegacyFirewall::get().hasStatsPermission(uid);
}
