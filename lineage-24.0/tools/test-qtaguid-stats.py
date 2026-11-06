#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile/test the real cumulative-stats parser against this kernel's schemas.
Usage: test-qtaguid-stats.py LIBNETWORKSTATS_DIR XT_QTAGUID_C
No tablet or host networking configuration is changed.
"""
import argparse
import hashlib
import os
import contextlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

HARNESS = r'''
#include "QtaguidStats.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <string>
#include <vector>
using namespace android::bpf::legacy;
static int cases;
static std::string row(int index = 2, const std::string& iface = "wlan0",
        const std::string& tag = "0x0", const std::string& uid = "10001",
        const std::string& set = "0", const std::string& rx = "100") {
    return std::to_string(index) + " " + iface + " " + tag + " " + uid + " " + set +
        " " + rx + " 2 200 3 100 2 0 0 0 0 200 3 0 0 0 0\n";
}
static std::vector<Record> check(std::string text, bool detail, int expected) {
    FILE* f = tmpfile(); assert(f);
    assert(fwrite(text.data(), 1, text.size(), f) == text.size()); rewind(f);
    Record sentinel; sentinel.iface = "unchanged";
    std::vector<Record> records{sentinel};
    int result = readStats(f, detail, &records);
    if (result != expected) {
        fprintf(stderr, "case %d: expected %d got %d\n", cases, expected, result); abort();
    }
    if (expected) assert(records.size() == 1 && records[0].iface == "unchanged");
    assert(fclose(f) == 0); ++cases;
    return records;
}
int main() {
    std::string d = detail_header, v = iface_header;
    auto r = check(d + row() + row(3, "wlan0", "0x100000000", "10001", "1"), true, 0);
    assert(r.size() == 2 && r[0].counters[0] == 100 && r[1].tag == 1 && r[1].set == 1);
    assert(check(d, true, 0).empty());
    assert(check(v, false, 0).empty());
    auto dev = check(v + "wlan0 100 2 200 3 100 2 0 0 0 0 200 3 0 0 0 0\n", false, 0);
    assert(dev.size() == 1 && dev[0].counters[2] == 200);
    check("", true, -EINVAL);
    check(v + row(), true, -EINVAL);
    check(d + "2 wlan0\n", true, -EINVAL);
    check(d + row(3), true, -EINVAL);
    check(d + row() + row(), true, -EINVAL);
    check(d + row() + row(3), true, -EINVAL);  // Duplicate key despite different index.
    check(d + row(2, "wlan0", "0x1"), true, -EINVAL);
    check(d + row(2, "wlan0", "123"), true, -EINVAL);
    check(d + row(2, "wlan0", "0x"), true, -EINVAL);
    check(d + row(2, "wlan0", "0x10000000000000000"), true, -EOVERFLOW);
    check(d + row(2, "wlan0", "0x0", "-1"), true, -EINVAL);
    check(d + row(2, "wlan0", "0x0", "+1"), true, -EINVAL);
    check(d + row(2, "wlan0", "0x0", "2147483648"), true, -EOVERFLOW);
    check(d + row(2, "wlan0", "0x0", "10001", "2"), true, -EINVAL);
    check(d + row(2, "wlan/0"), true, -EINVAL);
    check(d + row(2, "1234567890123456"), true, -EINVAL);
    check(d + row(2, "wlan0", "0x0", "10001", "0", "-1"), true, -EINVAL);
    check(d + row(2, "wlan0", "0x0", "10001", "0", "9223372036854775808"), true, -EOVERFLOW);
    auto max = check(d + row(2, "wlan0", "0xffffffff00000000", "10001", "0", "9223372036854775807"), true, 0);
    assert(max[0].tag == UINT32_MAX && max[0].counters[0] == INT64_MAX);
    auto bad = row(); bad.insert(bad.size() - 1, " extra");
    check(d + bad, true, -EINVAL);
    bad = row(); bad[bad.size() - 2] = 'x'; check(d + bad, true, -EINVAL);
    bad = row(); bad.insert(bad.size() - 1, 1, '\0'); check(d + bad, true, -EINVAL);
    check(d + std::string(5000, '1') + "\n", true, -EINVAL);
    bad = row(); bad.pop_back(); check(d + bad, true, 0);  // Complete final row, no newline.
    check(v + "wlan0 0 0\n", false, -EINVAL);
    check(d + row() + "bad\n", true, -EINVAL);  // No partially published valid first row.
    std::string big = d;
    for (int i = 0; i < 2000; ++i) big += row(i + 2, "wlan0", "0x0", std::to_string(10000 + i));
    assert(check(big, true, 0).size() == 2000);
    std::array<int64_t, 4> sum{0, 1, 2, 3};
    assert(addCounters({4, 5, 6, 7}, &sum) == 0 && sum[0] == 4 && sum[3] == 10); ++cases;
    auto before = sum;
    assert(addCounters({1, INT64_MAX, 1, 1}, &sum) == -EOVERFLOW && sum == before); ++cases;
    assert(addCounters({1, 1, -1, 1}, &sum) == -EINVAL && sum == before); ++cases;
    assert(readStats(nullptr, true, &r) == -EINVAL); ++cases;
    FILE* writeOnly = fopen("/dev/null", "w"); assert(writeOnly);
    assert(readStats(writeOnly, true, &r) == -EBADF); fclose(writeOnly); ++cases;
    printf("PASS: %d actual qtaguid parser/counter cases; kernel schemas verified.\n", cases);
}
'''


def kernel_header(source, function):
    start = source.index('static void ' + function + '(')
    block = source[start:source.index('\n}', start)]
    return ''.join(json.loads('"' + text + '"') for text in
                   re.findall(r'"((?:\\.|[^"\\])*)"', block))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('kernel', type=Path)
    parser.add_argument('--output', type=Path, help='New persistent evidence directory')
    args = parser.parse_args()
    if args.output:
        assert not args.output.exists()
        args.output.mkdir(parents=True)
    source = args.kernel.read_text()
    headers = ('static const char* detail_header = ' + json.dumps(kernel_header(source, 'pp_stats_header')) + ';\n'
               'static const char* iface_header = ' + json.dumps(kernel_header(source, 'pp_iface_stat_header')) + ';\n')
    context = contextlib.nullcontext(str(args.output.resolve())) if args.output else tempfile.TemporaryDirectory(prefix='gta3xlwifi-qtaguid-')
    with context as d:
        cpp, binary = Path(d) / 'test.cpp', Path(d) / 'test'
        cpp.write_text(headers + HARNESS)
        cmd = ['c++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        '-I' + str(args.library), str(cpp), str(args.library / 'QtaguidStats.cpp'),
                        '-o', str(binary)]
        built = subprocess.run(cmd, capture_output=True, text=True)
        assert built.returncode == 0, built.stderr
        env = os.environ.copy(); env['UBSAN_OPTIONS'] = 'halt_on_error=1'
        run = subprocess.run([str(binary)], capture_output=True, text=True, env=env)
        assert run.returncode == 0 and not run.stderr, (run.returncode, run.stdout, run.stderr)
        assert run.stdout == 'PASS: 36 actual qtaguid parser/counter cases; kernel schemas verified.\n', run.stdout
        print(run.stdout, end='')
        if args.output:
            paths = [Path(__file__).resolve(), args.kernel.resolve(), args.library.resolve()/'QtaguidStats.cpp', args.library.resolve()/'QtaguidStats.h']
            report = {'passed': True, 'passed_cases': 36, 'fatal_ubsan': True, 'stderr': run.stderr,
                      'command': cmd, 'inputs_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                      'real_kernel_schema_verified': True, 'hardware_tested': False, 'flash_ready': False}
            (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
