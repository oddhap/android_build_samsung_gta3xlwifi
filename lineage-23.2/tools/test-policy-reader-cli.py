#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CLI safety fixtures only, NOT policy/compiler/kernel execution validation."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ReaderSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='policy-reader-cli-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.kernel, self.inputs = self.root/'kernel', self.root/'inputs'
        self.kernel.mkdir()
        self.inputs.mkdir()
        self.policy = self.inputs/'policy'
        self.policy.write_bytes(b'CLI FIXTURE NOT A REAL POLICY')
        self.inspector = self.root/'missing-inspector'
        self.out = self.root/'result'
        self.tool = Path(__file__).with_name('check-kernel-policy-xperms.py')

    def run_tool(self, out=None):
        return subprocess.run([sys.executable, str(self.tool), '--inspector', str(self.inspector),
                               str(self.kernel), str(self.policy), str(out or self.out)],
                              capture_output=True, text=True, timeout=15)

    def test_source_output_rejected(self):
        self.assertNotEqual(self.run_tool(self.kernel/'result').returncode, 0)
        self.assertFalse((self.kernel/'result').exists())

    def test_exact_source_root_preserved(self):
        marker = self.kernel/'marker'
        marker.write_text('KEEP')
        self.assertNotEqual(self.run_tool(self.kernel).returncode, 0)
        self.assertEqual(marker.read_text(), 'KEEP')
        self.assertFalse((self.kernel/'report.json').exists())

    def test_policy_tree_output_rejected(self):
        self.assertNotEqual(self.run_tool(self.inputs/'result').returncode, 0)
        self.assertFalse((self.inputs/'result').exists())

    def test_existing_report_never_overwritten(self):
        self.out.mkdir()
        (self.out/'report.json').write_text('KEEP')
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertEqual((self.out/'report.json').read_text(), 'KEEP')

    def test_parent_alias_cannot_bypass_source_protection(self):
        alias = self.root/'alias'
        alias.symlink_to(self.kernel, target_is_directory=True)
        self.assertNotEqual(self.run_tool(alias/'result').returncode, 0)
        self.assertFalse((self.kernel/'result').exists())

    def test_missing_inspector_reports_failure_not_success(self):
        self.assertNotEqual(self.run_tool().returncode, 0)
        r = json.loads((self.out/'report.json').read_text())
        self.assertFalse(r['passed'])
        self.assertFalse(r['actual_kernel_execution'])
        self.assertFalse(r['whole_policy_load_proven'])
        self.assertIn('error', r)

    def test_bad_inspector_json_cannot_pass(self):
        self.inspector.write_text('#!/usr/bin/env python3\nprint("NOT JSON")\n')
        self.inspector.chmod(0o755)
        self.assertNotEqual(self.run_tool().returncode, 0)
        self.assertFalse(json.loads((self.out/'report.json').read_text())['passed'])

    def test_wrong_binary_version_is_not_accepted(self):
        self.inspector.write_text('#!/usr/bin/env python3\nprint(\'{"policy_binary_version":33}\')\n')
        self.inspector.chmod(0o755)
        self.assertNotEqual(self.run_tool().returncode, 0)
        r = json.loads((self.out/'report.json').read_text())
        self.assertFalse(r['passed'])
        self.assertIn('version-30', r['error'])


if __name__ == '__main__':
    unittest.main()
