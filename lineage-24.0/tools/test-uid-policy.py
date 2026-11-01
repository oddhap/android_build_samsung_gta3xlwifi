#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-test candidate policy against extracted upstream Android 17 DNS query code.
Android BPF map contents and SDK level are fixtures; decision functions are
extracted unchanged from pinned sources. No kernel rules, sockets or tablet I/O.
Usage: test-uid-policy.py STAGED_NETD_SERVER REFERENCE_CONNECTIVITY [--sanitize]
"""
import argparse
from pathlib import Path
import re
import random
import subprocess
import tempfile

PREFIX = r'''
#include "Gta3xlwifiUidPolicy.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/types.h>
using android::net::gta3xlwifi::UidPolicy;
#ifndef EUNATCH
#define EUNATCH 49
#endif
struct FakeError {
    int number;
    template<class T> FakeError operator<<(const T&) const { return *this; }
};
struct FakeLog { template<class T> FakeLog& operator<<(const T&) { return *this; } };
#define LOG(x) FakeLog()
namespace android::base {
inline FakeError Error(int error) { return {error}; }
template<class T> class Result {
 public:
    Result(T value) : mValue(value), mOk(true) {}
    Result(FakeError error) : mValue{}, mOk(false), mError(error) {}
    bool ok() const { return mOk; }
    T value() const { assert(mOk); return mValue; }
    FakeError error() const { return mError; }
 private:
    T mValue;
    bool mOk;
    FakeError mError{EIO};
};
}
namespace android::modules::sdklevel { inline bool IsAtLeastV() { return true; } }
#define RETURN_IF_RESULT_NOT_OK(r) do { if (!(r).ok()) return (r).error(); } while (0)
static constexpr unsigned AID_USER_OFFSET = 100000;
static constexpr unsigned AID_APP_START = 10000;
static constexpr unsigned UID_RULES_CONFIGURATION_KEY = 0;
static constexpr unsigned DATA_SAVER_ENABLED_KEY = 0;
using BpfConfig = uint32_t;
struct UidOwnerValue { uint32_t iif = 0; uint32_t rule = 0; };
template<class T> struct FixtureMap {
    T val{};
    bool present = true;
    uint32_t expectedKey = 0;
    bool isValid() const { return true; }
    android::base::Result<T> readValue(uint32_t key) const {
        assert(key == expectedKey);
        if (!present) return FakeError{ENOENT};
        return val;
    }
};
namespace android::net {
class DnsBpfHelper {
 public:
    FixtureMap<uint32_t> mConfigurationMap;
    FixtureMap<UidOwnerValue> mUidOwnerMap;
    FixtureMap<uint32_t> mDataSaverEnabledMap;
    base::Result<bool> isUidNetworkingBlocked(uid_t uid, bool metered);
};
}
'''
SUFFIX = r'''
static UidPolicy makePolicy(uint32_t config, uint32_t matches, bool saver, int32_t uid) {
    UidPolicy p;
    p.setDataSaver(saver);
    for (const auto& chain : UidPolicy::chains()) {
        assert(p.setChainEnabled(chain.id, config & chain.match) == 0);
        if (matches & chain.match) {
            assert(p.setUidRule(chain.id, uid, chain.allowlist ? UidPolicy::Allow : UidPolicy::Deny) == 0);
        }
    }
    return p;
}
static bool oracle(uint32_t uid, uint32_t config, uint32_t matches, bool saver, bool metered) {
    android::net::DnsBpfHelper helper;
    helper.mConfigurationMap.val = config;
    helper.mUidOwnerMap.expectedKey = uid;
    helper.mUidOwnerMap.val.rule = matches;
    helper.mUidOwnerMap.present = matches != 0;
    helper.mDataSaverEnabledMap.val = saver;
    auto result = helper.isUidNetworkingBlocked(uid, metered);
    assert(result.ok());
    return result.value();
}
int main(int argc, char**) {
    if (argc > 1) {  // stdin metadata stream for the separate Java source oracle.
        int32_t uid;
        uint32_t config, matches;
        int saver, metered;
        while (std::cin >> uid >> config >> matches >> saver >> metered) {
            auto p = makePolicy(config, matches, saver, uid);
            uint32_t reasons = UINT32_MAX;
            assert(p.blockedReasons(uid, &reasons) == 0);
            std::cout << reasons << ' ' << p.isNetworkingBlocked(uid, metered) << '\n';
        }
        return 0;
    }
    checkSourceBindings();
    unsigned apiChecks = 0;
    auto check = [&](bool result) { assert(result); ++apiChecks; };
    UidPolicy p;
    uint32_t reasons = 0xabcdef;
    int32_t rule = -7;
    bool enabled = true;
    check(p.blockedReasons(-1, &reasons) == -EINVAL && reasons == 0xabcdef);
    check(p.blockedReasons(10001, nullptr) == -EINVAL);
    check(p.isNetworkingBlocked(-1, false) == -EINVAL);
    check(p.setUidRule(0, 10001, 1) == -EINVAL);
    check(p.setUidRule(13, 10001, 1) == -EINVAL);
    check(p.setUidRule(1, -1, 1) == -EINVAL);
    check(p.setUidRule(1, 10001, 3) == -EINVAL);
    check(p.getUidRule(1, 10001, nullptr) == -EINVAL);
    check(p.getUidRule(13, 10001, &rule) == -EINVAL && rule == -7);
    check(p.getChainEnabled(0, &enabled) == -EINVAL && enabled);
    check(p.getChainEnabled(1, nullptr) == -EINVAL);
    check(p.setChainEnabled(-1, true) == -EINVAL);
    check(p.replaceUidChain(0, {}) == -EINVAL);
    check(p.removeUid(-1) == -EINVAL);
    for (const auto& c : UidPolicy::chains()) {
        check(p.getChainEnabled(c.id, &enabled) == 0 && !enabled);
        check(p.getUidRule(c.id, 10001, &rule) == 0 && rule == (c.allowlist ? 2 : 1));
        check(p.setUidRule(c.id, 10001, c.allowlist ? 1 : 2) == 0);
        check(p.getUidRule(c.id, 10001, &rule) == 0 && rule == (c.allowlist ? 1 : 2));
        check(p.setUidRule(c.id, 10001, 0) == 0);
        check(p.getUidRule(c.id, 10001, &rule) == 0 && rule == (c.allowlist ? 2 : 1));
        check(p.replaceUidChain(c.id, {10001, 10001, INT_MAX}) == 0);
        check(p.replaceUidChain(c.id, {10002, -1}) == -EINVAL);
        check(p.getUidRule(c.id, 10001, &rule) == 0 && rule == (c.allowlist ? 1 : 2));
        check(p.getUidRule(c.id, INT_MAX, &rule) == 0 && rule == (c.allowlist ? 1 : 2));
        check(p.replaceUidChain(c.id, {}) == 0);
    }
    check(p.setUidRule(1, 10001, 1) == 0);
    check(p.setUidRule(12, 10001, 2) == 0);
    check(p.replaceUidChain(1, {10002}) == 0);
    check(p.getUidRule(12, 10001, &rule) == 0 && rule == 2);
    check(p.removeUid(10001) == 0);
    check(p.getUidRule(12, 10001, &rule) == 0 && rule == 1);
    check(p.getUidRule(1, 10002, &rule) == 0 && rule == 1);
    uint64_t compared = 0;
    auto compare = [&](int32_t uid, uint32_t config, uint32_t matches, bool saver) {
        auto candidate = makePolicy(config, matches, saver, uid);
        for (bool metered : {false, true}) {
            assert(candidate.isNetworkingBlocked(uid, metered) ==
                   static_cast<int>(oracle(uid, config, matches, saver, metered)));
            ++compared;
        }
    };
    // Every enabled/UID combination of all nine non-metered chains.
    for (uint32_t config = 0; config < 512; ++config) {
        for (uint32_t matches = 0; matches < 512; ++matches) {
            uint32_t c = 0, m = 0;
            for (unsigned i = 0; i < 9; ++i) {
                if (config & (1u << i)) c |= UidPolicy::chains()[i].match;
                if (matches & (1u << i)) m |= UidPolicy::chains()[i].match;
            }
            compare(10001, c, m, false);
        }
    }
    // All metered membership/config bits, saver states, and core/app boundaries.
    for (int32_t uid : {0, 9999, 10000, 10001, 99999, 100000, 109999, 110000,
                        1010001, INT_MAX}) {
        for (uint32_t config = 0; config < 8; ++config) {
            for (uint32_t matches = 0; matches < 8; ++matches) {
                uint32_t c = 0, m = 0;
                for (unsigned i = 0; i < 3; ++i) {
                    if (config & (1u << i)) c |= UidPolicy::chains()[i + 9].match;
                    if (matches & (1u << i)) m |= UidPolicy::chains()[i + 9].match;
                }
                for (bool saver : {false, true}) compare(uid, c, m, saver);
            }
        }
        compare(uid, 0x3fff, 0, true);
        compare(uid, 0x3fff, 0x3fff, true);
    }
    // Chain reason bits, independent OR accumulation and per-user core bypass.
    for (const auto& c : UidPolicy::chains()) {
        UidPolicy q;
        if (!c.metered) check(q.setChainEnabled(c.id, true) == 0);
        if (!c.allowlist) check(q.setUidRule(c.id, 10001, 2) == 0);
        if (c.metered && c.allowlist) q.setDataSaver(true);
        check(q.blockedReasons(10001, &reasons) == 0 && reasons == c.blockedReason);
        check(q.blockedReasons(109999, &reasons) == 0 && reasons == 0);
    }
    std::cout << "API checks: " << apiChecks << "; actual upstream DNS oracle comparisons: "
              << compared << '\n';
}
'''


def function(text, start):
    begin = text.index(start)
    return text[begin:text.index('\n}\n', begin) + 3]


def source(staged, reference):
    header = (reference / 'bpf/progs/netd.h').read_text()
    enum = re.search(r'enum UidOwnerMatchType[^\{]*\{.*?\};', header, re.S).group()
    defines = '\n'.join(re.findall(r'^#define DROP_IF_.*$', header.replace('\\\n', ' '), re.M))
    helpers = function(header, 'static inline bool isBlockedByUidRules(')
    helpers += function(header, 'static inline bool is_system_uid(')
    dns = (reference / 'bpf/dns_helper/DnsBpfHelper.cpp').read_text()
    query = function(dns, 'base::Result<bool> DnsBpfHelper::isUidNetworkingBlocked(')
    assert 'sLegacyDnsPolicy' not in query, 'Oracle must be unmodified upstream source'
    bindings, _ = source_bindings(reference)
    return PREFIX + enum + '\n' + defines + '\n' + helpers + '\nnamespace android::net {\n' + query + '\n}\n' + bindings + SUFFIX


def java_constants(text):
    result = {}
    for kind, name, value in re.findall(r'public static final (int|long|short) (\w+)\s*=\s*([^;]+);', text):
        if re.fullmatch(r'[0-9a-fA-FxX()<>\s]+', value):
            result[name] = (kind, value.strip())
    return result


def chain_lists(text):
    result = {}
    for name in ('ALLOW_CHAINS', 'DENY_CHAINS', 'METERED_ALLOW_CHAINS', 'METERED_DENY_CHAINS'):
        body = re.search(r'\b' + name + r'\s*=\s*List.of\((.*?)\);', text, re.S).group(1)
        result[name] = re.findall(r'FIREWALL_CHAIN_\w+', body)
    return result


def source_bindings(reference):
    framework = reference / 'framework/src/android/net'
    cm = java_constants((framework / 'ConnectivityManager.java').read_text())
    constants = (framework / 'BpfNetMapsConstants.java').read_text()
    bpf = java_constants(constants)
    utils = (framework / 'BpfNetMapsUtils.java').read_text()
    matches = re.findall(r'case (FIREWALL_CHAIN_\w+):\s*return (\w+);', utils)
    assert len(matches) == 12, 'Unexpected upstream firewall-chain definitions'
    lists = chain_lists(constants)
    allow = set(lists['ALLOW_CHAINS'] + lists['METERED_ALLOW_CHAINS'])
    metered = set(lists['METERED_ALLOW_CHAINS'] + lists['METERED_DENY_CHAINS'])
    reasons = ['BLOCKED_REASON_DOZE', 'BLOCKED_REASON_APP_STANDBY', 'BLOCKED_REASON_BATTERY_SAVER',
               'BLOCKED_REASON_RESTRICTED_MODE', 'BLOCKED_REASON_LOW_POWER_STANDBY',
               'BLOCKED_REASON_APP_BACKGROUND', 'BLOCKED_REASON_OEM_DENY', 'BLOCKED_REASON_OEM_DENY',
               'BLOCKED_REASON_OEM_DENY', 'BLOCKED_METERED_REASON_DATA_SAVER',
               'BLOCKED_METERED_REASON_USER_RESTRICTED', 'BLOCKED_METERED_REASON_ADMIN_DISABLED']
    code = ['static void checkSourceBindings() {']
    for chain, match in matches:
        chain_id = int(cm[chain][1])
        fields = {'id': cm[chain][1], 'match': bpf[match][1],
                  'blockedReason': cm[reasons[chain_id - 1]][1],
                  'allowlist': str(chain in allow).lower(), 'metered': str(chain in metered).lower()}
        for field, value in fields.items():
            code.append(f'assert(UidPolicy::chains()[{chain_id - 1}].{field} == ({value}));')
    for native, upstream in [('MeteredReasonMask', 'BLOCKED_METERED_REASON_MASK'),
                             ('DataSaverReason', 'BLOCKED_METERED_REASON_DATA_SAVER')]:
        code.append(f'assert(UidPolicy::{native} == ({cm[upstream][1]}));')
    for native, upstream in [('Default', 'FIREWALL_RULE_DEFAULT'), ('Allow', 'FIREWALL_RULE_ALLOW'),
                             ('Deny', 'FIREWALL_RULE_DENY')]:
        code.append(f'assert(UidPolicy::{native} == ({cm[upstream][1]}));')
    return '\n'.join(code) + '\n}\n', (cm, bpf, utils, lists)


def java_function(text, start):
    begin = text.index(start)
    return text[begin:text.index('\n    }', begin) + 6]


def java_oracle(reference, java_bin, tmp, native):
    _, (cm, bpf, utils, lists) = source_bindings(reference)
    fields = {name: pair for name, pair in cm.items()
              if name.startswith(('BLOCKED_', 'FIREWALL_CHAIN_', 'FIREWALL_RULE_'))}
    fields.update(bpf)
    declarations = '\n'.join(f'static final {kind} {name} = {value};'
                             for name, (kind, value) in fields.items())
    list_fields = '\n'.join(f'static final java.util.List<Integer> {name} = java.util.List.of('
                            + ','.join(values) + ');' for name, values in lists.items())
    mask_start = utils.index('private static final long sMaskDropIfSet;')
    masks = utils[mask_start:utils.index('// Prevent this class', mask_start)]
    methods = '\n'.join(java_function(utils, start) for start in (
        'public static long getMatchByFirewallChain(', 'public static int getUidNetworkingBlockedReasons(',
        'public static boolean isUidNetworkingBlocked(', 'public static boolean getDataSaverEnabled('))
    fixtures = r'''
static final int EINVAL = 22;
static final S32 UID_RULES_CONFIGURATION_KEY = new S32(0);
static final S32 DATA_SAVER_ENABLED_KEY = new S32(0);
static void throwIfPreT(String msg) {} // Target fixed at A16, not an SDK compatibility test.
static class Struct { static class S32 { int val; S32(int v) { val=v; } } }
static class S32 extends Struct.S32 { S32(int v) { super(v); } }
static class U32 { long val; U32(long v) { val=v; } }
static class U8 { short val; U8(int v) { val=(short)v; } }
static class UidOwnerValue { long rule; UidOwnerValue(long v) { rule=v; } }
interface IBpfMap<K,V> { V getValue(Object key) throws ErrnoException; }
static class ErrnoException extends Exception { private static final long serialVersionUID=1L; int errno; }
static class ServiceSpecificException extends RuntimeException {
    private static final long serialVersionUID=1L;
    ServiceSpecificException(int code, String message) { super(message); }
}
static class Os { static String strerror(int code) { return "fixture-error"; } }
static class UserHandle { static int getAppId(int uid) { return uid % 100000; } }
static class Process { static final int FIRST_APPLICATION_UID=10000; }
public static void main(String[] ignored) throws Exception {
    var reader=new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
    for(String line; (line=reader.readLine())!=null;) {
        String[] parts=line.split(" "); int uid=Integer.parseInt(parts[0]);
        long config=Long.parseLong(parts[1]), matches=Long.parseLong(parts[2]);
        int saver=Integer.parseInt(parts[3]); boolean metered=parts[4].equals("1");
        IBpfMap<S32,U32> c=key->{if(((Struct.S32)key).val!=0) throw new AssertionError(); return new U32(config);};
        IBpfMap<S32,UidOwnerValue> u=key->{if(((Struct.S32)key).val!=uid) throw new AssertionError();
            return matches==0?null:new UidOwnerValue(matches);};
        IBpfMap<S32,U8> d=key->{if(((Struct.S32)key).val!=0) throw new AssertionError(); return new U8(saver);};
        System.out.println(getUidNetworkingBlockedReasons(uid,c,u,d)+" "+(isUidNetworkingBlocked(uid,metered,c,u,d)?1:0));
    }
}
'''
    java = tmp / 'Oracle.java'
    java.write_text('public class Oracle {\n' + declarations + '\n' + fixtures + '\n' +
                    'static class BpfNetMapsConstants {\n' + list_fields + '\n}\n' + masks + methods + '\n}\n')
    subprocess.run([str(java_bin / 'javac'), '-Xlint:all', '-Werror', '-d', str(tmp), str(java)], check=True)
    rng = random.Random(20261021)
    cases = []
    for uid in (0, 9999, 10000, 10001, 100000, 109999, 110000, 1010001, 2147483647):
        for config in (0, 0x3fff):
            for matches in (0, 0x3fff):
                for saver in (0, 1):
                    for metered in (0, 1): cases.append((uid, config, matches, saver, metered))
    for _ in range(8192):
        cases.append((rng.randint(0, 2147483647), rng.randrange(0x4000), rng.randrange(0x4000),
                      rng.randrange(2), rng.randrange(2)))
    data = ''.join(' '.join(map(str, row)) + '\n' for row in cases)
    actual = subprocess.check_output([str(native), '--stream'], input=data, text=True)
    expected = subprocess.check_output([str(java_bin / 'java'), '-cp', str(tmp), 'Oracle'], input=data, text=True)
    assert actual == expected, 'Native reason/decision differs from extracted Android 17 Java implementation'
    print(f'Actual upstream Java reason/decision oracle comparisons: {len(cases)}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('staged', type=Path)
    parser.add_argument('reference', type=Path)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--java-bin', type=Path, help='Optional JDK bin directory for extracted Java oracle')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='gta-uid-policy-') as directory:
        tmp = Path(directory)
        cpp = tmp / 'test.cpp'
        cpp.write_text(source(args.staged, args.reference))
        exe = tmp / 'test'
        command = ['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O1',
                   '-g', '-I' + str(args.staged), str(cpp),
                   str(args.staged / 'Gta3xlwifiUidPolicy.cpp'), '-o', str(exe)]
        if args.sanitize:
            command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(command, check=True)
        subprocess.run([str(exe)], check=True)
        if args.java_bin:
            java_oracle(args.reference, args.java_bin.resolve(), tmp, exe)


if __name__ == '__main__':
    main()
