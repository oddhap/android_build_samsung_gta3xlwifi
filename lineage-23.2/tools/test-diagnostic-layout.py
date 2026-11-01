#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CLI safety fixtures only, not actual filesystem/Android compatibility tests."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).with_name('check-diagnostic-layout.py')


class Safety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.top = self.root / 'android'
        self.top.mkdir()
        self.archive = self.root / 'archive.json'
        self.output = self.root / 'output'

    def run_cli(self, output=None):
        return subprocess.run([sys.executable, str(TOOL), str(self.top), str(self.archive),
                               str(output or self.output)], capture_output=True, text=True)

    def assert_report_failure(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads((self.output / 'report.json').read_text())
        self.assertFalse(report['passed'])
        self.assertFalse(report['hardware_tested'])
        self.assertEqual(list(self.top.iterdir()), [])

    def test_reject_source_child(self):
        output = self.top / 'out' / 'scratch'
        self.assertEqual(self.run_cli(output).returncode, 2)
        self.assertFalse((self.top / 'out').exists())

    def test_reject_source_root(self):
        self.assertEqual(self.run_cli(self.top).returncode, 2)
        self.assertEqual(list(self.top.iterdir()), [])

    def test_reject_source_symlink_alias(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.top, target_is_directory=True)
        self.assertEqual(self.run_cli(alias / 'scratch').returncode, 2)
        self.assertFalse((self.top / 'scratch').exists())

    def test_never_overwrite_output(self):
        self.output.mkdir()
        sentinel = self.output / 'sentinel'
        sentinel.write_text('KEEP')
        self.assertNotEqual(self.run_cli().returncode, 0)
        self.assertEqual(sentinel.read_text(), 'KEEP')
        self.assertFalse((self.output / 'report.json').exists())

    def test_missing_archive(self):
        self.assert_report_failure()

    def test_invalid_json(self):
        self.archive.write_text('{ not JSON')
        self.assert_report_failure()

    def test_unverified_archive(self):
        self.archive.write_text(json.dumps({'archive_crc_passed': False}))
        self.assert_report_failure()

    def test_stale_image_digest(self):
        image = self.root / 'image'
        image.write_bytes(b'changed')
        self.archive.write_text(json.dumps({'archive_crc_passed': True, 'images': {
            'system.img': {'path': str(image), 'sha256': hashlib.sha256(b'original').hexdigest(),
                           'expanded_bytes': 0}}}))
        self.assert_report_failure()
        self.assertEqual(image.read_bytes(), b'changed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
