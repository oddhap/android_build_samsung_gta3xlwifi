#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile/link the entire staged ARM64 or ARM32 DNS helper outside TOP/out.
Uses the actual completed Soong link edge and its saved response file. Never
runs Ninja builds, changes flags to hide errors, creates BPF state or installs.
Checks dynamic symbol/version surface, not complete header ABI or runtime.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess

LIB = 'packages/modules/Connectivity/bpf/dns_helper'
MODULE = 'libcom.android.tethering.dns_helper'
VARIANTS = {
    'arm64': ('android_arm64_armv8-a_shared_cfi_apex31',
              'android_arm64_armv8-a_static_cfi_apex31_sabi', 2, 183),
    'arm32': ('android_arm_armv8-a_shared_cfi', 'android_arm_armv8-a_static_cfi', 1, 40),
}
FILES = ('DnsBpfHelper.cpp', 'DnsHelper.cpp')
MAP = MODULE + '.map.txt'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emitted(top, target):
    text = subprocess.check_output([str(top / 'prebuilts/build-tools/linux-x86/bin/ninja'),
                                   '-f', 'out/combined-lineage_gta3xlwifi.ninja',
                                   '-t', 'commands', target], cwd=top, text=True)
    argv = shlex.split(text.splitlines()[-1])
    if any(token in ('&&', ';', '|', '>', '>>') for token in argv):
        raise ValueError('Shell composition in compiler/linker command is not permitted')
    return argv


def check(top, staged, output, report, abi):
    variant, source_variant, elf_class, machine = VARIANTS[abi]
    module = 'out/soong/.intermediates/' + LIB + '/' + MODULE + '/'
    target = module + variant + '/unstripped/' + MODULE + '.so'
    link = emitted(top, target)
    compiler = link[0]
    if not (compiler.startswith('prebuilts/clang/') and compiler.endswith('/clang++')):
        raise ValueError('Unexpected link tool')
    if link.count('-o') != 1 or link[link.index('-o') + 1] != target:
        raise ValueError('Unexpected link output')
    if '-Wl,--no-undefined' not in link or '-Wl,--fatal-warnings' not in link:
        raise ValueError('Expected strict linker flags are missing')
    # No unredirected map/dependency/cache/plugin output flags are accepted.
    if any(re.search(r'(?:[Mm]ap=|cache-dir|save-temps|dependency-file|remark)', x) for x in link):
        raise ValueError('Unrecognized secondary linker output')
    rsp = [x for x in link if x.startswith('@')]
    if rsp != ['@' + target + '.rsp']:
        raise ValueError('Unexpected link response file')
    inputs = shlex.split((top / (target + '.rsp')).read_text())
    old_inputs = inputs.copy()
    if any(x.startswith(('-', '@')) for x in inputs):
        raise ValueError('Expected only input paths in saved response file')
    report['source_sha256'] = {str(p.relative_to(staged)): sha(p) for p in staged.rglob('*')
                               if p.is_file() and (p.suffix in ('.h', '.cpp') or p.name == MAP)}
    report['original_response_sha256'] = sha(top / (target + '.rsp'))
    env = dict(os.environ, CCACHE_DISABLE='1', PWD='/proc/self/cwd')
    for name in FILES:
        original = module + source_variant + '/obj/' + LIB + '/' + name[:-4] + '.o'
        if inputs.count(original) != 1:
            raise ValueError('Missing/duplicate source object: ' + original)
        compile_args = emitted(top, original)
        if (compile_args[:2] != ['PWD=/proc/self/cwd', '/usr/bin/ccache']
                or compile_args[2] != compiler or compile_args[-1] != LIB + '/' + name
                or compile_args.count('-o') != 1 or compile_args.count('-MF') != 1):
            raise ValueError('Unexpected source compiler edge')
        command = compile_args[1:]
        obj = output / (name + '.o')
        command[command.index('-o') + 1] = str(obj)
        command[command.index('-MF') + 1] = str(output / (name + '.d'))
        command[-1] = str(staged / name)
        command[3:3] = ['-I' + str(staged), '-I' + str(staged / 'include')]
        with (output / (name + '.log')).open('w') as log:
            subprocess.run(command, cwd=top, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        inputs[inputs.index(original)] = str(obj)
        report['compiles'].append({'source': name, 'argv': command, 'exit_code': 0})
    if len(inputs) != len(old_inputs):
        raise ValueError('Unexpected link input count')
    for item in inputs:
        if not (top / item).is_file():
            raise ValueError('Missing link dependency: ' + item)
    new_rsp = output / 'link.rsp'
    new_rsp.write_text(' '.join(shlex.quote(x) for x in inputs) + '\n')
    result = output / (MODULE + '.so')
    link[link.index('-o') + 1] = str(result)
    link[link.index(rsp[0])] = '@' + str(new_rsp)
    script = '-Wl,--version-script,' + LIB + '/' + MAP
    if link.count(script) != 1:
        raise ValueError('Unexpected version script')
    link[link.index(script)] = '-Wl,--version-script,' + str(staged / MAP)
    report['link_argv'] = link
    with (output / 'link.log').open('w') as log:
        subprocess.run(link, cwd=top, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    elf = result.read_bytes()
    if elf[:5] != b'\x7fELF' + bytes([elf_class]) or struct.unpack_from('<H', elf, 18)[0] != machine:
        raise ValueError('Result is not the requested ARM ELF class/machine')
    bin_dir = (top / compiler).parent

    def symbols(path):
        text = subprocess.check_output([str(bin_dir / 'llvm-nm'), '-D', '--defined-only',
                                        '--format=posix', str(path)], text=True)
        return sorted(line.split()[0] for line in text.splitlines() if line.strip())

    def dynamic(path):
        text = subprocess.check_output([str(bin_dir / 'llvm-readelf'), '-d', str(path)], text=True)
        return sorted(re.findall(r'\((NEEDED|SONAME)\).*?\[(.*?)\]', text))

    before, after = symbols(top / target), symbols(result)
    new = [x for x in after if x not in before]
    if set(before) - set(after) or len(new) != 1 or new[0].split('@')[0] != 'ADnsHelper_setLegacyCallbackV2':
        raise ValueError('Unexpected versioned dynamic symbol change: ' + repr(new))
    if dynamic(top / target) != dynamic(result):
        raise ValueError('SONAME or dependency surface changed')
    report.update(passed=True, output_sha256=sha(result), original_symbols=before,
                  staged_symbols=after, added_symbols=new, needed_soname=dynamic(result),
                  strict_link_flags_preserved=True, complete_helper_shared_library_linked=True,
                  full_header_abi_checked=False, android_runtime_executed=False,
                  kernel_backend_ready=False, tablet_modified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--abi', choices=VARIANTS, default='arm64')
    parser.add_argument('top', type=Path)
    parser.add_argument('staged', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    top, staged, output = (p.resolve() for p in (args.top, args.staged, args.output))
    if any(p == top or top in p.parents for p in (staged, output)):
        parser.error('Staged sources and output must be outside TOP/out')
    output.mkdir(parents=True, exist_ok=False)
    report = {'passed': False, 'started_at_utc': datetime.now(timezone.utc).isoformat(),
              'scope': 'Complete isolated CFI DNS shared-helper link and dynamic surface only',
              'abi': args.abi, 'variant': VARIANTS[args.abi][0], 'compiles': []}
    try:
        check(top, staged, output, report, args.abi)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    report['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('DNS helper isolated full link:', 'PASS' if report['passed'] else report.get('error', 'FAIL'))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
