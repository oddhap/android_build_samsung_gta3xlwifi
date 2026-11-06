// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "IptablesRestoreController.h"

namespace android::net::gta3xlwifi {

// Checked updates of EXISTING owned chains in ONE address family. This is an
// I/O component, not complete packet policy, cross-family atomicity, attachment
// ownership, startup, persistence or network readiness. Its caller must be the
// sole owner and hold the netd firewall transaction lock across each operation.
class CheckedUidChains {
public:
    struct UidRange {
        uint32_t first;
        uint32_t last;
        bool operator==(const UidRange& b) const { return first == b.first && last == b.last; }
    };
    enum class Verdict { Return, Drop };
    struct Rule {
        std::optional<UidRange> uid;
        Verdict verdict;
        bool operator==(const Rule& b) const { return uid == b.uid && verdict == b.verdict; }
    };
    struct Chain {
        std::string name;
        std::vector<Rule> rules;
        bool operator==(const Chain& b) const { return name == b.name && rules == b.rules; }
    };
    explicit CheckedUidChains(IptablesRestoreInterface& kernel) : mKernel(kernel) {}
    int read(IptablesTarget family, const std::vector<std::string>& names,
             std::vector<Chain>* output);
    // Success requires exact ordered kernel readback. Any failed write or
    // mismatch restores the actual before-image and verifies it. -EUCLEAN means
    // restoration could not be verified: caller MUST quarantine/fail closed;
    // no callback, readiness or cached policy may be published from this result.
    int replace(IptablesTarget family, const std::vector<Chain>& desired);

private:
    int readLocked(IptablesTarget family, const std::vector<std::string>& names,
                   std::vector<Chain>* output);
    int writeLocked(IptablesTarget family, const std::vector<Chain>& image);
    static int encode(const std::vector<Chain>& image, std::string* output);
    static bool validNames(const std::vector<std::string>& names);
    static bool validImage(const std::vector<Chain>& image);
    IptablesRestoreInterface& mKernel;
    std::mutex mMutex;
};

}  // namespace android::net::gta3xlwifi
