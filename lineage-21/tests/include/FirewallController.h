#pragma once
#include "NetdConstants.h"
namespace android::net {
struct FirewallController {
    static std::string makeCriticalCommands(IptablesTarget target, const char* chain) {
        return target == V6 ? "-A " + std::string(chain) + " -p ipv6-icmp --icmpv6-type neighbour-solicitation -j RETURN\n" : "";
    }
};
}
