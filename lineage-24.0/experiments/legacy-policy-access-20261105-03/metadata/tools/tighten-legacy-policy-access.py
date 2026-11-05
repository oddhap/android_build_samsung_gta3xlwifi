#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Remove reviewed obsolete grants and retire the Android11 MLS compatibility escape.

Offline proposal based on platform-policy-port-20261105-03. No new allow or
attribute membership is introduced. Current Android17 and Samsung vendor
assertions remain unchanged. Strict compilation only; no image or TOP edits.
"""
import argparse
import copy
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

GRANTS = [
    ('(allow crash_dump_30_0 vold_30_0 (process (ptrace)))', 1,
     'Android17 private/crash_dump.te:143 protects vold from debugger attachment.'),
    ('(allow dumpstate_30_0 vold_30_0 (binder (call)))', 2,
     'Android17 private/dumpstate.te:490 forbids dumpstate calling vold.'),
    ('(allow platform_app_30_0 shell_data_file_30_0 (file (execute execute_no_trans)))', 1,
     'Android17 private/shell.te:675 forbids platform applications executing shell data.'),
    ('(allow zygote_30_0 setupwizard_prop (property_service (set)))', 1,
     'Android17 private/property.te:780 restricts setupwizard writers.'),
    ('(allow scs setupwizard_prop (property_service (set)))', 1,
     'Android17 private/property.te:780 restricts setupwizard writers.'),
    ('(allow vendor_init_30_0 setupwizard_prop (property_service (set)))', 1,
     'Android17 private/property.te:780 and shared ownership assertions restrict setupwizard writers.'),
]
MLS = [
    '(typeattributeset mlsvendorcompat (and appdomain vendordomain))',
    '(allow mlsvendorcompat app_data_file (dir (ioctl read write create getattr setattr lock rename open watch watch_reads add_name remove_name reparent search rmdir)))',
    '(allow mlsvendorcompat app_data_file (file (ioctl read write create getattr setattr lock append map unlink rename open watch watch_reads)))',
    '(allow mlsvendorcompat privapp_data_file (dir (ioctl read write create getattr setattr lock rename open watch watch_reads add_name remove_name reparent search rmdir)))',
    '(allow mlsvendorcompat privapp_data_file (file (ioctl read write create getattr setattr lock append map unlink rename open watch watch_reads)))',
]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    base = json.loads(a.baseline.read_text())
    assert not base['passed_strict']
    command = list(base['results'][0]['command'])
    assert base['results'][0]['mode'] == 'strict' and '-N' not in command
    top = Path('/srv/android/src/lineage-24.0-arm64')
    output = a.output.resolve()
    assert not output.exists() and not output.is_relative_to(top)
    sha = lambda data: hashlib.sha256(data).hexdigest()
    vendors = [Path(x['path']) for x in base['inputs'] if Path(x['path']).name == 'vendor_sepolicy.cil']
    assert len(vendors) == 1
    inputs = {Path(x['path']): x['sha256'] for x in base['inputs']}
    inputs[Path(command[0])] = base['compiler_sha256']
    for path, expected in inputs.items():
        assert not output.is_relative_to(path.parent)
        assert sha(path.read_bytes()) == expected, path
    vendor = vendors[0]
    compat = Path(base['build_output_root'])/'target/product/gta3xlwifi/system/etc/selinux/mapping/30.0.compat.cil'
    assert compat in inputs
    assert sha(vendor.read_bytes()) == '1b962ef17897b4decab0293ca9161c26be35194904f198908fdac369da0b39f5'
    assert sha(compat.read_bytes()) == '2b40198379e1bb65ca2af156b25562381273144d94c5ae223b5ed9905d7437cc'
    original = {vendor: vendor.read_text(), compat: compat.read_text()}
    staged = dict(original)
    ledger = []
    for path, rules in [(vendor, GRANTS), (compat, [(s, 1, 'Retire MLS escape prohibited by Android17 private/domain.te:2257; retain ordinary MLS constraints.') for s in MLS])]:
        for statement, count, reason in rules:
            assert staged[path].splitlines().count(statement) == count, statement
            staged[path] = staged[path].replace(statement+'\n', '\n')
            ledger.append({'input': str(path), 'statement': statement, 'occurrences': count, 'reason': reason})
    spec = importlib.util.spec_from_file_location('cil', Path(__file__).with_name('stage-vendor-uwb-namespace.py'))
    cil = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cil)
    spec2 = importlib.util.spec_from_file_location('forms', Path(__file__).with_name('stage-platform-policy-port.py'))
    forms = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(forms)
    for path in [vendor, compat]:
        before = [original[path][s:e] for _, s, e in forms.statements(original[path], cil.tokens)]
        after = [staged[path][s:e] for _, s, e in forms.statements(staged[path], cil.tokens)]
        removed = {x['statement'] for x in ledger if x['input'] == str(path)}
        assert [s for s in before if s not in removed] == after
    before_counts, after_counts = cil.rule_counts(original[vendor]), cil.rule_counts(staged[vendor])
    assert after_counts == dict(before_counts, allow=before_counts['allow']-7)
    output.mkdir(parents=True)
    (output/'tools').mkdir()
    for name in ['tighten-legacy-policy-access.py', 'stage-vendor-uwb-namespace.py', 'stage-platform-policy-port.py']:
        (output/'tools'/name).write_bytes(Path(__file__).with_name(name).read_bytes())
    replacements = {}
    for path, text in staged.items():
        dest = output/path.name
        dest.write_text(text)
        replacements[str(path)] = str(dest)
        (output/(path.name+'.patch')).write_text(''.join(difflib.unified_diff(original[path].splitlines(True), text.splitlines(True), fromfile=str(path), tofile=str(dest))))
    (output/'removed-grants.json').write_text(json.dumps(ledger, indent=2)+'\n')
    strict = output/'strict'
    strict.mkdir()
    command = [replacements.get(x, x) for x in command]
    command[command.index('-o')+1] = str(strict/'strict.policy')
    result = subprocess.run(command, capture_output=True, text=True)
    (strict/'strict.log').write_text(result.stdout+result.stderr)
    report = copy.deepcopy(base)
    report.pop('checked_at_utc', None)
    report['passed_strict'] = result.returncode == 0
    report['inputs'] = [{'path': replacements.get(str(path), str(path)),
                         'sha256': sha(Path(replacements.get(str(path), str(path))).read_bytes())}
                        for path in [Path(x['path']) for x in base['inputs']]]
    report['results'] = [{'mode': 'strict', 'exit_code': result.returncode,
                          'neverallow_checks_enabled': True, 'command': command}]
    if result.returncode == 0:
        report['results'][0]['compiled_policy_sha256'] = sha((strict/'strict.policy').read_bytes())
    (strict/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    for path, expected in inputs.items():
        assert sha(path.read_bytes()) == expected, path
    summary = {'scope': __doc__, 'removed_vendor_allow_statements': 7,
               'vendor_rules_before': before_counts, 'vendor_rules_after': after_counts,
               'retired_compat_allow_statements': 4, 'retired_mls_membership_assignments': 1,
               'all_retained_statements_byte_exact': True,
               'no_new_rule_or_attribute_membership': True,
               'strict_passed': result.returncode == 0, 'compiler_exit': result.returncode,
               'diagnostic_blocks': (result.stdout+result.stderr).count('neverallow check failed at '),
               'baseline_report_sha256': sha(a.baseline.read_bytes()),
               'runner_sha256': sha(Path(__file__).read_bytes()),
               'original_inputs_and_compiler_unchanged': True,
               'runtime_and_app_mls_labels_validated': False, 'security_approved': False, 'flash_ready': False}
    (output/'report.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))
    assert result.returncode in [0, 255], 'Unexpected compiler/tool failure'


if __name__ == '__main__':
    main()
