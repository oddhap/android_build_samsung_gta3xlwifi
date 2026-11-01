#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile staged NetworkStatsFactory with its real Soong SDK/compiler flags.
Only one production source is compiled, not a complete module or Android tests.
Wait until Soong graph generation has finished before reading its Ninja commands.
Usage: compile-network-java-staging.py TOP STAGED_NETWORK_STATS_FACTORY NEW_OUTPUT
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

MODULE = 'service-connectivity-tiramisu-pre-jarjar'
JAR = ('out/soong/.intermediates/packages/modules/Connectivity/service-t/' + MODULE +
       '/android_common/javac/' + MODULE + '.jar')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('top', type=Path)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    top, source, output = (p.resolve() for p in (args.top, args.source, args.output))
    if top in source.parents or top == output or top in output.parents:
        parser.error('Staging/output must be outside the active source tree')
    if source.name != 'NetworkStatsFactory.java':
        parser.error('Unexpected source')
    output.mkdir(parents=True, exist_ok=False)
    report = {'passed': False, 'scope': 'one production Java source, actual Soong SDK/compiler flags',
              'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'complete_module_built': False, 'java_tests_compiled_or_run': False}
    try:
        emitted = subprocess.check_output([
            str(top / 'prebuilts/build-tools/linux-x86/bin/ninja'),
            '-f', 'out/combined-lineage_gta3xlwifi.ninja', '-t', 'commands', JAR],
            cwd=top, text=True)
        lines = [line for line in emitted.splitlines() if 'soong_javac_wrapper' in line]
        tokens = shlex.split(lines[-1])
        start = next(i for i, token in enumerate(tokens) if token.endswith('/soong_javac_wrapper')) + 1
        end = next((i for i in range(start, len(tokens)) if tokens[i] in ('&&', ';', ')')), len(tokens))
        command = [arg for arg in tokens[start:end] if not arg.startswith('@')]
        if (not command[0].startswith('prebuilts/jdk/') or not command[0].endswith('/javac')
                or any(command.count(flag) != 1 for flag in ('-d', '-s', '-classpath'))):
            raise ValueError('Unexpected javac command; refusing to execute')
        for flag, directory in (('-d', 'classes'), ('-s', 'generated')):
            destination = output / directory
            destination.mkdir()
            command[command.index(flag) + 1] = str(destination)
        if not (top / JAR).is_file():
            raise ValueError('Original compiled module JAR is unavailable')
        index = command.index('-classpath') + 1
        # Resolve sibling/package-private classes from the existing actual module,
        # not invented Android API fixtures. This source overrides its old class.
        command[index] = JAR + ':' + command[index]
        command += ['-J-XX:ErrorFile=' + str(output / 'hs_err_pid%p.log'), str(source)]
        report['argv'] = command
        with (output / 'javac.log').open('w') as log:
            result = subprocess.run(command, cwd=top, env=dict(os.environ),
                                    stdout=log, stderr=subprocess.STDOUT)
        report['exit_code'] = result.returncode
        report['passed'] = result.returncode == 0
        print('NetworkStatsFactory.java isolated compilation: exit', result.returncode)
    except (OSError, ValueError, IndexError, StopIteration, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print('Java preflight could not complete:', error)
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
