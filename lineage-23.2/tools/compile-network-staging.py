#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile isolated networking WIP with real Soong flags, without editing TOP/out.
This is compile-only preflight, NOT a linked module, ROM or runtime validation.
Usage: compile-network-staging.py [--component stats|dns|uid-policy|qtaguid-socket] TOP STAGED_LIBRARY NEW_OUTPUT
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

LIB = 'packages/modules/Connectivity/service-t/native/libs/libnetworkstats'
VARIANTS = ('android_arm64_armv8-a_static', 'android_arm_armv8-a_static',
            'android_arm64_armv8-a_static_cfi_apex31', 'android_arm_armv8-a_static_cfi')
COMPONENTS = {
    'stats': (LIB, 'libnetworkstats',
              ('QtaguidStats.cpp', 'Gta3xlwifiLegacyStats.cpp', 'BpfNetworkStats.cpp'),
              'BpfNetworkStats.cpp'),
    'dns': ('packages/modules/Connectivity/bpf/dns_helper',
            'libcom.android.tethering.dns_helper',
            ('DnsBpfHelper.cpp', 'DnsHelper.cpp'), 'DnsBpfHelper.cpp'),
    'qtaguid-socket': ('system/netd/server', 'libnetd_server',
                       ('Gta3xlwifiQtaguidTransport.cpp',), 'FirewallController.cpp'),
    'uid-policy': ('system/netd/server', 'libnetd_server',
                   ('Gta3xlwifiUidPolicy.cpp',), 'FirewallController.cpp'),
}
COMPONENT_VARIANTS = {
    # netd is a primary-ABI daemon on this product, not a 32-bit client library.
    'uid-policy': ('android_arm64_armv8-a_static_cfi',),
    'qtaguid-socket': ('android_arm64_armv8-a_static_cfi',),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=COMPONENTS, default='stats')
    parser.add_argument('top', type=Path)
    parser.add_argument('staged', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    library, module, files, reference = COMPONENTS[args.component]
    top, staged, output = (p.resolve() for p in (args.top, args.staged, args.output))
    if staged == top or top in staged.parents or output == top or top in output.parents:
        parser.error('Staging and outputs must be outside the active Android tree')
    for name in files:
        if not (staged / name).is_file():
            parser.error('Missing staged source: ' + str(staged / name))
    output.mkdir(parents=True, exist_ok=False)
    report = {'started_at_utc': datetime.now(timezone.utc).isoformat(),
              'scope': 'isolated compile-only, actual Soong flags, no linking or source edits',
              'component': args.component,
              'source_sha256': {str(p.relative_to(staged)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in staged.rglob('*') if p.suffix in ('.cpp', '.h') and p.is_file()},
              'compiles': [], 'passed': False}
    env = dict(os.environ, CCACHE_DISABLE='1', PWD='/proc/self/cwd')
    try:
        for variant in COMPONENT_VARIANTS.get(args.component, VARIANTS):
            target = ('out/soong/.intermediates/' + library + '/' + module + '/' + variant +
                      '/obj/' + library + '/' + reference.removesuffix('.cpp') + '.o')
            emitted = subprocess.check_output([
                str(top / 'prebuilts/build-tools/linux-x86/bin/ninja'),
                '-f', 'out/combined-lineage_gta3xlwifi.ninja', '-t', 'commands', target],
                cwd=top, text=True)
            argv = shlex.split(emitted.splitlines()[-1])
            if (argv[:2] != ['PWD=/proc/self/cwd', '/usr/bin/ccache']
                    or not argv[2].startswith('prebuilts/clang/') or not argv[2].endswith('/clang++')
                    or argv[-1] != library + '/' + reference
                    or argv.count('-o') != 1 or argv.count('-MF') != 1):
                raise ValueError('Unexpected compiler command; refusing to execute')
            # No shell evaluation. Redirect both object/dependency outputs out of TOP.
            base = argv[1:]
            for name in files:
                result_dir = output / variant
                result_dir.mkdir(exist_ok=True)
                command = base.copy()
                command[command.index('-o') + 1] = str(result_dir / (name + '.o'))
                command[command.index('-MF') + 1] = str(result_dir / (name + '.d'))
                command[-1] = str(staged / name)
                command.insert(3, '-I' + str(staged))
                if (staged / 'include').is_dir():
                    command.insert(3, '-I' + str(staged / 'include'))
                with (result_dir / (name + '.log')).open('w') as log:
                    result = subprocess.run(command, cwd=top, env=env, stdout=log, stderr=subprocess.STDOUT)
                report['compiles'].append({'variant': variant, 'source': name,
                                           'exit_code': result.returncode, 'argv': command})
                print(f'{variant} {name}: exit {result.returncode}', flush=True)
                if result.returncode:
                    raise RuntimeError('Compilation failed: ' + str(result_dir / (name + '.log')))
        report['passed'] = True
    finally:
        report['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
