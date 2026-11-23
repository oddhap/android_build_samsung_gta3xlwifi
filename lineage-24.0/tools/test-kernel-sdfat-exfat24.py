#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host checks for the sdfat "exfat" alias candidate source tree."""
import argparse
import json
import re
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    text = (args.source / 'fs/sdfat/sdfat.c').read_text()
    cases = []

    def check(name, ok):
        cases.append({'case': name, 'passed': bool(ok)})

    types = re.findall(r'static struct file_system_type (\w+) = \{(.*?)\n\};', text, re.S)
    by_name = {n: body for n, body in types}
    check('two_fs_types', sorted(by_name) == ['exfat_fs_type', 'sdfat_fs_type'])
    sd, ex = by_name.get('sdfat_fs_type', ''), by_name.get('exfat_fs_type', '')
    check('sdfat_name_kept', '.name        = "sdfat"' in sd)
    check('exfat_name', '.name        = "exfat"' in ex)
    check('same_mount', '.mount       = sdfat_fs_mount' in sd and '.mount       = sdfat_fs_mount' in ex)
    check('same_teardown', sd.replace('"sdfat"', 'X') == ex.replace('"exfat"', 'X'))
    check('requires_dev', 'FS_REQUIRES_DEV' in ex)
    init = text[text.index('static int __init init_sdfat_fs'):text.index('static void __exit exit_sdfat_fs')]
    i_sd = init.index('register_filesystem(&sdfat_fs_type)')
    i_ex = init.index('register_filesystem(&exfat_fs_type)')
    check('register_order', i_sd < i_ex < init.index('return 0;'))
    check('alias_failure_unregisters_sdfat',
          'unregister_filesystem(&sdfat_fs_type);\n\t\tgoto error;' in init[i_ex:])
    exitf = text[text.index('static void __exit exit_sdfat_fs'):]
    check('exit_unregisters_both', exitf.index('unregister_filesystem(&exfat_fs_type)')
          < exitf.index('unregister_filesystem(&sdfat_fs_type)') < exitf.index('fsapi_shutdown()'))
    check('single_exfat_registration',
          len(re.findall(r'(?<!un)register_filesystem\(&exfat_fs_type\)', text)) == 1
          and text.count('unregister_filesystem(&exfat_fs_type)') == 1)
    passed = all(c['passed'] for c in cases)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'report.json').write_text(json.dumps(
        {'passed': passed, 'passed_cases': sum(c['passed'] for c in cases), 'cases': cases}, indent=2) + '\n')
    print(json.dumps({'passed': passed, 'cases': len(cases)}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
