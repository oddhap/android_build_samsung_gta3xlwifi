#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CLI safety tests using temporary fixtures, NOT real policy/VINTF validation."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent


def put(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class ValidationSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vendor-validation-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.top, self.vendor = self.root / 'top', self.root / 'vendor'
        self.out = self.top / 'out/target/product/gta3xlwifi'
        self.result = self.root / 'result'
        self.policy = self.vendor / 'etc/selinux'
        put(self.policy / 'plat_sepolicy_vers.txt', '30.0\n')
        for name in ['plat_pub_versioned.cil', 'vendor_sepolicy.cil']:
            put(self.policy / name, '; fixture only\n')
        for name in ['plat_sepolicy.cil', 'mapping/30.0.cil']:
            put(self.out / 'system/etc/selinux' / name, '; fixture only\n')
        put(self.top / 'system/sepolicy/compat/libgenfslabelsversion/src/lib.rs',
            'const DEFAULT_GENFS_LABELS_VERSION: i32 = 202404;')
        put(self.top / 'system/core/init/selinux.cpp', '"-m", "-M", "true", "-G", "-N"')
        self.compiler = put(self.top / 'out/host/linux-x86/bin/secilc', '''#!/usr/bin/env python3
import pathlib,sys
assert sys.argv[sys.argv.index('-c')+1] == '30'
if '-N' not in sys.argv: sys.exit(42)
pathlib.Path(sys.argv[sys.argv.index('-o')+1]).write_bytes(b'UNIT TEST FIXTURE')
''')
        self.compiler.chmod(0o755)

    def run_tool(self, name, *extra):
        return subprocess.run([sys.executable, str(TOOLS / name), '--top', str(self.top),
                               '--vendor', str(self.vendor), '--output', str(self.result), *extra],
                              capture_output=True, text=True)

    def report(self):
        return json.loads((self.result / 'report.json').read_text())

    def test_runtime_link_success_cannot_override_strict_failure(self):
        result = self.run_tool('check-vendor-policy.py', '--runtime-diagnostic')
        self.assertEqual(result.returncode, 1)
        report = self.report()
        self.assertFalse(report['passed_strict'])
        self.assertEqual([r['exit_code'] for r in report['results']], [42, 0])
        self.assertNotIn('-N', report['results'][0]['command'])
        self.assertIn('-N', report['results'][1]['command'])

    def test_default_has_no_runtime_assertion_bypass(self):
        self.assertEqual(self.run_tool('check-vendor-policy.py').returncode, 1)
        self.assertEqual(len(self.report()['results']), 1)
        self.assertTrue(self.report()['results'][0]['neverallow_checks_enabled'])

    def test_missing_required_mapping_stops_before_compilation(self):
        (self.out / 'system/etc/selinux/mapping/30.0.cil').unlink()
        self.assertNotEqual(self.run_tool('check-vendor-policy.py').returncode, 0)
        self.assertFalse(self.result.exists())

    def test_modern_genfs_fragment_cannot_be_silently_omitted(self):
        put(self.policy / 'genfs_labels_version.txt', '202504\n')
        self.assertNotEqual(self.run_tool('check-vendor-policy.py').returncode, 0)
        self.assertFalse(self.result.exists())

    def test_unknown_source_genfs_default_is_rejected(self):
        put(self.top / 'system/sepolicy/compat/libgenfslabelsversion/src/lib.rs',
            'changed implementation requiring review')
        self.assertNotEqual(self.run_tool('check-vendor-policy.py').returncode, 0)
        self.assertFalse(self.result.exists())

    def test_invalid_vendor_version_is_rejected(self):
        put(self.policy / 'plat_sepolicy_vers.txt', '../wrong')
        self.assertNotEqual(self.run_tool('check-vendor-policy.py').returncode, 0)
        self.assertFalse(self.result.exists())

    def test_existing_output_is_not_overwritten(self):
        self.result.mkdir()
        marker = put(self.result / 'report.json', 'KEEP')
        self.assertNotEqual(self.run_tool('check-vendor-policy.py').returncode, 0)
        self.assertEqual(marker.read_text(), 'KEEP')

    def test_explicit_build_output_uses_only_that_policy_and_compiler(self):
        isolated = self.top / 'out-isolated'
        shutil.copytree(self.top / 'out', isolated)
        shutil.rmtree(self.top / 'out')  # fixture only; prohibit implicit fallback
        result = self.run_tool('check-vendor-policy.py', '--out-dir', 'out-isolated',
                               '--runtime-diagnostic')
        self.assertEqual(result.returncode, 1)
        report = self.report()
        self.assertEqual(report['build_output_root'], str(isolated))
        self.assertEqual([r['exit_code'] for r in report['results']], [42, 0])
        for entry in report['results']:
            self.assertEqual(entry['command'][0], str(isolated / 'host/linux-x86/bin/secilc'))
        self.assertTrue(all(Path(i['path']).is_relative_to(isolated) or
                            Path(i['path']).is_relative_to(self.vendor)
                            for i in report['inputs']))

    def test_invalid_build_output_paths_are_rejected(self):
        for path in ['', '.', '..', '../out', 'out/../out', str(self.top / 'out')]:
            with self.subTest(path=path):
                self.assertNotEqual(self.run_tool('check-vendor-policy.py',
                                                 '--out-dir', path).returncode, 0)
                self.assertFalse(self.result.exists())

    def test_build_output_symlink_cannot_escape_top(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.top / 'escape').symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.run_tool('check-vendor-policy.py',
                                         '--out-dir', 'escape').returncode, 0)
        self.assertFalse(self.result.exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_report_must_not_write_into_source_or_vendor(self):
        for protected in [self.top, self.vendor]:
            with self.subTest(protected=protected):
                target = protected / 'must-not-be-created'
                self.assertNotEqual(self.run_tool('check-vendor-policy.py',
                                                 '--output', str(target)).returncode, 0)
                self.assertFalse(target.exists())

    def test_report_parent_symlink_cannot_bypass_tree_protection(self):
        alias = self.root / 'output-alias'
        alias.symlink_to(self.vendor, target_is_directory=True)
        self.assertNotEqual(self.run_tool('check-vendor-policy.py', '--output',
                                         str(alias / 'must-not-be-created')).returncode, 0)
        self.assertFalse((self.vendor / 'must-not-be-created').exists())

    def test_vintf_failure_retains_kernel_and_vendor_inputs(self):
        for level in ['3', '7', '8', '202404', '202504', '202604', 'device']:
            put(self.out / f'system/etc/vintf/compatibility_matrix.{level}.xml', '<fixture/>')
        put(self.out / 'system/etc/vintf/manifest.xml', '<fixture/>')
        for name in ['manifest.xml', 'compatibility_matrix.xml']:
            put(self.vendor / 'etc/vintf' / name, '<fixture/>')
        kernel = put(self.root / 'kernel.config', 'CONFIG_FIXTURE=y\n')
        checker = put(self.top / 'out/host/linux-x86/bin/checkvintf', '''#!/usr/bin/env python3
import sys
assert '--kernel' in sys.argv
assert any(a.startswith('/vendor:') for a in sys.argv)
assert any(a.startswith('/apex:') for a in sys.argv)
sys.exit(65)
''')
        checker.chmod(0o755)
        self.assertEqual(self.run_tool('check-vendor-vintf.py', '--kernel-config', str(kernel)).returncode, 1)
        report = self.report()
        self.assertEqual(report['exit_code'], 65)
        self.assertFalse(report['passed'])
        self.assertFalse(report['complete_post_apex_validation_proven'])
        self.assertFalse(report['kernel_requirements_ignored_or_edited_by_this_tool'])


if __name__ == '__main__':
    unittest.main()
