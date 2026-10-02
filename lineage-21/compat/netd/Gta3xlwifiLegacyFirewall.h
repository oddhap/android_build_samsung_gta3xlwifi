// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <map>
#include <set>
#include <string>
#include <vector>
namespace android::net {
// Caller holds netd's global lock. Rules are committed to IPv4 and IPv6 before
// updating the state used to build subsequent transactions.
class Gta3xlwifiLegacyFirewall {
public:
    static bool enabled();
    static Gta3xlwifiLegacyFirewall& get();
    int setUidRule(int chain, int uid, int rule);
    int enableChain(int chain, bool enable);
    int replaceChain(const std::string& name, bool allowlist, const std::vector<int32_t>& uids);
    int setIngressDiscard(const std::string& address, const std::string& iface, bool add);
    void setDataSaverState(bool enabled) { mDataSaver = enabled; }
    void setPermissions(int permissions, const std::vector<int32_t>& uids);
    bool isUidBlocked(int uid, bool metered) const;
    bool hasStatsPermission(int uid) const;
    int setMeteredUid(int uid, bool nice, bool add);
    int setInterfaceRules(const std::string& iface, const std::vector<int32_t>& uids);
    int removeInterfaceRules(const std::vector<int32_t>& uids);
private:
    struct Chain { std::set<int> uids; bool enabled = false; };
    std::map<int, Chain> mChains;
    std::set<int> mNice, mNaughty;
    std::map<int, std::string> mInterfaces;
    std::set<int> mLockdown;
    std::map<std::string, std::string> mIngress;
    std::map<int, int> mPermissions;
    bool mDataSaver = false;
    bool mInitialized = false;
    int init();
    static const char* name(int chain);
    static bool allowlist(int chain);
    static int applyChain(int chain, const Chain& value);
    int applyAttachments(const std::map<int, Chain>& chains);
    int applyIngress(const std::map<std::string, std::string>& values);
    int applyInterfaces(const std::map<int, std::string>& values);
};
}

extern "C" bool gta3xlwifi_legacy_is_uid_networking_blocked(unsigned uid, bool metered);
extern "C" bool gta3xlwifi_legacy_has_stats_permission(unsigned uid);

// Private port integration; not part of the netd updatable SDK header.
extern "C" int libnetd_updatable_setLegacyCallbacks(bool (*blocked)(unsigned, bool),
                                                  bool (*permission)(unsigned));
