#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check that the 32-bit shim loads against VNDK v30 + system LLNDK.

Every NEEDED library must resolve like on the device: VNDK v30 (core/sp,
32-bit snapshot used to build com.android.vndk.v30) or a system LLNDK
library. Every undefined dynamic symbol must be defined by one of them.
This proves symbol-level loadability only, not runtime behaviour.
"""
import hashlib, json, subprocess, sys
from pathlib import Path

so, output = Path(sys.argv[1]), Path(sys.argv[2])
assert not output.exists()
T = Path('/srv/android/src/lineage-24.0-arm64')
V = T/'prebuilts/vndk/v30/arm64/arch-arm-armv8-a/shared'
SYS = T/'out/target/product/gta3xlwifi/system/lib'
LLNDK = {'libc.so', 'libm.so', 'libdl.so', 'liblog.so', 'libbinder_ndk.so', 'libvndksupport.so',
         'libnativewindow.so', 'libsync.so', 'libandroid_net.so', 'libmediandk.so', 'libvulkan.so',
         'libEGL.so', 'libGLESv1_CM.so', 'libGLESv2.so', 'libGLESv3.so', 'libft2.so'}


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(*a):
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout


needed = [l.split('[')[1].split(']')[0] for l in run('readelf', '-d', str(so)).splitlines() if '(NEEDED)' in l]
resolved, missing_libs = {}, []
for n in needed:
    for c in (V/'vndk-sp'/n, V/'vndk-core'/n):
        if c.exists():
            resolved[n] = c
            break
    else:
        bionic = T/'out/target/product/gta3xlwifi/apex/com.android.runtime/lib/bionic'/n
        if n in ('libc.so', 'libm.so', 'libdl.so') and bionic.exists():
            resolved[n] = bionic
        elif n in LLNDK and (SYS/n).exists():
            resolved[n] = SYS/n
        else:
            missing_libs.append(n)
defined = set()
for p in resolved.values():
    for l in run('nm', '-D', '--defined-only', str(p)).splitlines():
        parts = l.split()
        if len(parts) >= 3:
            defined.add(parts[2].split('@')[0])
undefined = []
for l in run('nm', '-D', '--undefined-only', str(so)).splitlines():
    parts = l.split()
    if parts and parts[0] in ('U', 'w', 'v'):
        name = parts[-1].split('@')[0]
        if parts[0] == 'U' and name not in defined:
            undefined.append(name)
report = {'passed': not missing_libs and not undefined, 'scope': __doc__, 'shim_sha256': sha(so),
          'needed': {n: str(p) for n, p in resolved.items()}, 'missing_libraries': missing_libs,
          'unresolved_symbols': sorted(undefined), 'runtime_tested': False}
output.write_text(json.dumps(report, indent=2)+'\n')
print('PASS' if report['passed'] else 'FAIL', 'needed', len(needed), 'missing libs', missing_libs,
      'unresolved', len(undefined))
for u in sorted(undefined)[:40]:
    print('  ', subprocess.run(['c++filt', u], capture_output=True, text=True).stdout.strip())
sys.exit(0 if report['passed'] else 1)
