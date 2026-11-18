#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise both observed LMKD startup paths and the retained userspace path."""
import subprocess
import sys
import tempfile
from pathlib import Path

prefix = r'''
#include <cassert>
#include <cstdlib>
#define ALOGE(...) ((void)0)
#define ALOGW(...) ((void)0)
#define ALOGI(...) ((void)0)
#define exit(code) throw code
bool use_inkernel_interface, monitors_initialized, boot_completed, init_ok;
int calls, memevents, direct_reclaim_threshold_ms;
bool property_get_bool(const char*, bool){ return boot_completed; }
bool init_monitors(){ ++calls; return init_ok; }
bool init_memevent_listener_monitoring(){ ++memevents; return init_ok; }
enum { LMK_START_MONITORING };
'''
suffix = r'''
int monitor(int nargs) {
    try { command(nargs); return 0; } catch (int e) { return e; }
}
int main(int argc, char**) {
    bool original = argc > 1;
    use_inkernel_interface = boot_completed = true;
    assert(monitor(0) == (original ? 1 : 0));
    init_memevent();
    assert(calls == (original ? 1 : 0));
    assert(memevents == (original ? 1 : 0));
    assert(monitor(1) == 2);
    use_inkernel_interface = false;
    calls = memevents = 0;
    boot_completed = false;
    assert(monitor(0) == 0 && calls == 0);
    boot_completed = true;
    monitors_initialized = true;
    assert(monitor(0) == 0 && calls == 0);
    monitors_initialized = false;
    assert(monitor(0) == 1 && calls == 1);
    direct_reclaim_threshold_ms = 21;
    init_memevent();
    assert(memevents == 1 && direct_reclaim_threshold_ms == 0);
    init_ok = true;
    assert(monitor(0) == 0 && calls == 2);
    direct_reclaim_threshold_ms = 21;
    init_memevent();
    assert(memevents == 2 && direct_reclaim_threshold_ms == 21);
}
'''
if len(sys.argv) != 3:
    raise SystemExit("Usage: test-lmkd-inkernel-boot24.py ORIGINAL_CPP FIXED_CPP")

with tempfile.TemporaryDirectory() as temp:
    for original, name in enumerate(reversed(sys.argv[1:])):
        source = Path(name).read_text()
        start = source.index('    case LMK_START_MONITORING:')
        end = source.index('    case LMK_BOOT_COMPLETED:', start)
        init = source.index('static void init_memevent() {')
        next_func = source.index('static bool init_psi_monitors()', init)
        test = Path(temp) / 'test.cpp'
        test.write_text(prefix + 'void command(int nargs){switch(LMK_START_MONITORING){\n'
                        + source[start:end] + '} return; wronglen: throw 2;}\n'
                        + source[init:next_func] + suffix)
        binary = Path(temp) / 'test'
        subprocess.run(['c++', '-Wall', '-Wextra', '-Werror', str(test), '-o', str(binary)], check=True)
        subprocess.run([str(binary)] + (['original'] if original else []), check=True)
print('Original failures reproduced. Kernel and userspace boot paths and failure handling passed.')
