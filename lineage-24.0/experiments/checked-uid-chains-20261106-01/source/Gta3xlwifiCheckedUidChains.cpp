// SPDX-License-Identifier: Apache-2.0
#include "Gta3xlwifiCheckedUidChains.h"

#include <cerrno>
#include <charconv>
#include <climits>
#include <set>
#include <sstream>
#include <string_view>

namespace android::net::gta3xlwifi {
namespace {
constexpr size_t kMaximumImageBytes = 1024 * 1024;

bool singleFamily(IptablesTarget family) { return family == V4 || family == V6; }

bool number(std::string_view text, uint32_t* output) {
    if (text.empty()) return false;
    // Numeric UID output from libxt_owner's save formatter, never names/signs.
    for (char c : text) if (c < '0' || c > '9') return false;
    uint32_t value = 0;
    auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value > INT_MAX)
        return false;
    *output = value;
    return true;
}

bool range(std::string_view text, CheckedUidChains::UidRange* output) {
    const size_t dash = text.find('-');
    uint32_t first = 0, last = 0;
    if (dash == std::string_view::npos) {
        if (!number(text, &first)) return false;
        last = first;
    } else if (!number(text.substr(0, dash), &first) ||
               !number(text.substr(dash + 1), &last) || first > last) {
        return false;
    }
    *output = {first, last};
    return true;
}
}  // namespace

bool CheckedUidChains::validNames(const std::vector<std::string>& names) {
    if (names.empty() || names.size() > 64) return false;
    std::set<std::string> unique;
    for (const auto& name : names) {
        if (name.size() < 5 || name.size() > 28 || name.rfind("g24_", 0) != 0 ||
            !unique.insert(name).second) return false;
        for (char c : name) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_')) return false;
        }
    }
    return true;
}

bool CheckedUidChains::validImage(const std::vector<Chain>& image) {
    std::vector<std::string> names;
    size_t rules = 0;
    for (const auto& chain : image) {
        names.push_back(chain.name);
        if (chain.rules.size() > 65536) return false;
        rules += chain.rules.size();
        if (rules > 65536) return false;
        for (const auto& rule : chain.rules) {
            if (rule.verdict != Verdict::Return && rule.verdict != Verdict::Drop) return false;
            if (rule.uid && (rule.uid->first > rule.uid->last || rule.uid->last > INT_MAX))
                return false;
        }
    }
    return validNames(names);
}

int CheckedUidChains::readLocked(IptablesTarget family, const std::vector<std::string>& names,
                                std::vector<Chain>* output) {
    if (!singleFamily(family) || !output || !validNames(names)) return -EINVAL;
    std::string commands = "*filter\n";
    for (const auto& name : names) commands += "-S " + name + "\n";
    commands += "COMMIT\n";
    std::string text;
    if (mKernel.execute(family, commands, &text)) return -EREMOTEIO;
    if (text.size() > kMaximumImageBytes || text.find('\0') != std::string::npos ||
        text.find('\r') != std::string::npos) return -EPROTO;
    for (unsigned char c : text) {
        if ((c < 32 && c != '\n' && c != '\t') || c == 127) return -EPROTO;
    }
    std::vector<Chain> next;
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream input(line);
        std::vector<std::string> tokens;
        std::string token;
        while (input >> token) tokens.push_back(token);
        if (tokens.empty()) continue;
        if (tokens.size() == 2 && tokens[0] == "-N") {
            if (next.size() >= names.size() || tokens[1] != names[next.size()]) return -EPROTO;
            next.push_back({tokens[1], {}});
            continue;
        }
        if (next.empty() || (tokens.size() != 4 && tokens.size() != 8) ||
            tokens[0] != "-A" || tokens[1] != next.back().name) return -EPROTO;
        const size_t jump = tokens.size() - 2;
        if (tokens[jump] != "-j" || (tokens[jump + 1] != "RETURN" && tokens[jump + 1] != "DROP"))
            return -EPROTO;
        Rule rule{std::nullopt, tokens[jump + 1] == "RETURN" ? Verdict::Return : Verdict::Drop};
        if (tokens.size() == 8) {
            UidRange uid{};
            if (tokens[2] != "-m" || tokens[3] != "owner" || tokens[4] != "--uid-owner" ||
                !range(tokens[5], &uid)) return -EPROTO;
            rule.uid = uid;
        }
        next.back().rules.push_back(rule);
    }
    std::string rollback;
    if (next.size() != names.size() || encode(next, &rollback)) return -EPROTO;
    *output = std::move(next);
    return 0;
}

int CheckedUidChains::encode(const std::vector<Chain>& image, std::string* output) {
    if (!validImage(image)) return -EINVAL;
    std::string commands = "*filter\n";
    for (const auto& chain : image) {
        commands += ":" + chain.name + " -\n";
        for (const auto& rule : chain.rules) {
            commands += "-A " + chain.name;
            if (rule.uid) {
                commands += " -m owner --uid-owner " + std::to_string(rule.uid->first);
                if (rule.uid->last != rule.uid->first)
                    commands += "-" + std::to_string(rule.uid->last);
            }
            commands += rule.verdict == Verdict::Return ? " -j RETURN\n" : " -j DROP\n";
            if (commands.size() > kMaximumImageBytes) return -E2BIG;
        }
    }
    commands += "COMMIT\n";
    if (commands.size() > kMaximumImageBytes) return -E2BIG;
    *output = std::move(commands);
    return 0;
}

int CheckedUidChains::writeLocked(IptablesTarget family, const std::vector<Chain>& image) {
    std::string commands;
    int result = encode(image, &commands);
    if (result) return result;
    return mKernel.execute(family, commands, nullptr) ? -EREMOTEIO : 0;
}

int CheckedUidChains::read(IptablesTarget family, const std::vector<std::string>& names,
                          std::vector<Chain>* output) {
    std::lock_guard<std::mutex> lock(mMutex);
    return readLocked(family, names, output);
}

int CheckedUidChains::replace(IptablesTarget family, const std::vector<Chain>& desired) {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!singleFamily(family)) return -EINVAL;
    std::string validated;
    int encoded = encode(desired, &validated);
    if (encoded) return encoded;
    std::vector<std::string> names;
    for (const auto& chain : desired) names.push_back(chain.name);
    std::vector<Chain> before, after;
    int result = readLocked(family, names, &before);
    if (result) return result;  // No write without a complete real before-image.
    if (before == desired) return 0;  // Already verified against actual kernel output.
    result = writeLocked(family, desired);
    if (!result && !readLocked(family, names, &after) && after == desired) return 0;
    // Even an error acknowledgement can follow a committed kernel transaction.
    // Restore the actual read snapshot, not a userspace cache, and verify it.
    if (writeLocked(family, before) || readLocked(family, names, &after) || after != before)
        return -EUCLEAN;
    return -EREMOTEIO;
}

}  // namespace android::net::gta3xlwifi
