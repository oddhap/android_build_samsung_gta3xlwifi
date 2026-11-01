#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test production DNS callback gate + extracted resolver decision function.
Only Android property/experiment/network-metadata calls are host fixtures.
No sockets, network configuration or tablet access.
Usage: test-legacy-dns-policy.py DNS_HELPER_DIR DNS_PROXY_LISTENER_CPP
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

PREFIX = r'''
#include "LegacyDnsPolicy.h"
#include <atomic>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <thread>
using android::net::LegacyDnsPolicy;
static bool legacy = true, enforceDnsUid = false, experiment = true, netMetered = false;
static uid_t seenUid;
static bool seenMetered;
static int answer;
static int allow(uid_t, bool) { return 0; }
static int block(uid_t, bool) { return 1; }
static int record(uid_t uid, bool metered) { seenUid = uid; seenMetered = metered; return answer; }
namespace android::base { bool GetBoolProperty(const char*, bool) { return legacy; } }
namespace android::net {
class Experiments {
 public:
  static Experiments* getInstance() { static Experiments e; return &e; }
  bool getFlag(const char*, int) { return experiment; }
};
}
static bool resolv_is_metered_network(unsigned) { return netMetered; }
static bool resolv_is_enforceDnsUid_enabled_network(unsigned) { return enforceDnsUid; }
// Android 17 links the helper directly. A missing owner returns errno,
// rather than representing an absent dynamic function symbol.
static int (*dnsReply)(uid_t, bool) = record;
static int ADnsHelper_isUidNetworkingBlocked(uid_t uid, bool metered) {
    return dnsReply ? dnsReply(uid, metered) : -ENOTCONN;
}
static bool isAtLeastT() { return true; }  // Fixed Android 17 SDK fixture.
using android::net::Experiments;
'''
SUFFIX = r'''
int main() {
    int cases = 0;
    auto check = [&](bool condition) { assert(condition); ++cases; };
    LegacyDnsPolicy p;
    check(!p.ready());
    check(p.evaluate(0, false) == -ENOTCONN);  // No implicit core-UID bypass.
    check(p.setCallback(nullptr) == -EINVAL);
    check(!p.ready());
    check(p.setCallback(record) == 0);
    check(p.ready());
    check(p.setCallback(record) == 0);
    check(p.setCallback(allow) == -EALREADY);
    answer = 0; check(p.evaluate(1010001, true) == 0);
    check(seenUid == 1010001 && seenMetered);
    answer = 1; check(p.evaluate(10001, false) == 1);
    check(seenUid == 10001 && !seenMetered);
    answer = -EIO; check(p.evaluate(10001, false) == -EIO);
    answer = -4095; check(p.evaluate(10001, false) == -4095);
    answer = -4096; check(p.evaluate(10001, false) == -EPROTO);
    answer = INT_MIN; check(p.evaluate(10001, false) == -EPROTO);
    answer = 2; check(p.evaluate(10001, false) == -EPROTO);
    answer = INT_MAX; check(p.evaluate(10001, false) == -EPROTO);
    LegacyDnsPolicy concurrent;
    int first = 1, second = 1;
    std::atomic<bool> done{false}, reading{false}, start{false};
    std::atomic<unsigned> arrived{0};
    std::thread reader([&] {
        while (!done.load()) {
            int r = concurrent.evaluate(10001, true);
            assert(r == -ENOTCONN || r == 0 || r == 1);
            reading.store(true);
        }
    });
    auto registerPolicy = [&](LegacyDnsPolicy::Callback callback, int* result) {
        arrived.fetch_add(1);
        while (!start.load()) std::this_thread::yield();
        *result = concurrent.setCallback(callback);
    };
    std::thread a(registerPolicy, allow, &first), b(registerPolicy, block, &second);
    // Force a live reader and both registering threads before releasing them.
    while (arrived.load() != 2 || !reading.load()) std::this_thread::yield();
    start.store(true);
    a.join(); b.join(); done.store(true); reader.join();
    check((first == 0 && second == -EALREADY) || (second == 0 && first == -EALREADY));
    check(concurrent.ready());
    legacy = true;
    dnsReply = nullptr;
    check(isUidNetworkingBlocked(0, 1));
    check(isUidNetworkingBlocked(10001, 1));
    dnsReply = record;
    answer = -EIO; check(isUidNetworkingBlocked(10001, 1));
    answer = 1; check(isUidNetworkingBlocked(10001, 1));
    answer = 2; check(isUidNetworkingBlocked(10001, 1));
    answer = 0; check(!isUidNetworkingBlocked(10001, 1));
    netMetered = true; check(!isUidNetworkingBlocked(1010001, 5));
    check(seenUid == 1010001 && seenMetered);
    enforceDnsUid = true; experiment = false;
    answer = 1; check(isUidNetworkingBlocked(10001, 1));  // Cannot bypass legacy policy.
    answer = -EIO; check(isUidNetworkingBlocked(10001, 1));
    legacy = false;
    check(!isUidNetworkingBlocked(10001, 1));  // Unmodified upstream OEM exemption.
    enforceDnsUid = false;
    check(!isUidNetworkingBlocked(10001, 1));  // Unmodified upstream feature flag.
    experiment = true;
    answer = 1; check(isUidNetworkingBlocked(10001, 1));
    answer = 0; check(!isUidNetworkingBlocked(10001, 1));
    dnsReply = nullptr;
    check(!isUidNetworkingBlocked(10001, 1));  // Upstream, not legacy, behavior.
    printf("PASS: %d production DNS gate/resolver cases (including registration race).\n", cases);
}
'''


def extract(source):
    start = source.index('bool isUidNetworkingBlocked(uid_t uid, unsigned netId) {')
    pos = source.index('{', start)
    depth = 1
    while depth:
        pos += 1
        depth += (source[pos] == '{') - (source[pos] == '}')
    return source[start:pos + 1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('helper', type=Path)
    parser.add_argument('proxy', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='gta3xlwifi-dns-') as d:
        source, binary = Path(d) / 'test.cpp', Path(d) / 'test'
        source.write_text(PREFIX + extract(args.proxy.read_text()) + SUFFIX)
        subprocess.run(['c++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pthread',
                        '-I' + str(args.helper), str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
