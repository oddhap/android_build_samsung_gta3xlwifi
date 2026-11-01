#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host safety regressions. Fixtures do not replace actual built-APK validation."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).with_name('check-app-partitions.py')
spec = importlib.util.spec_from_file_location('app_partitions', TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def line(name, partition='product', cert='testkey.pem', key='testkey.pk8'):
    return f'name="{name}.apk" certificate="{cert}" private_key="{key}" partition="{partition}"\n'


BEFORE = ''.join(line(app) for app in module.APPS) + line('Unrelated', 'data')
AFTER = ''.join(line(app, 'system') for app in module.APPS) + line('Unrelated', 'data')


class Metadata(unittest.TestCase):
    def test_only_three_partition_changes(self):
        self.assertEqual(module.validate_metadata(BEFORE, AFTER, AFTER)['records_checked'], 4)

    def test_order_does_not_matter(self):
        reverse = '\n'.join(reversed(AFTER.splitlines()))
        self.assertTrue(module.validate_metadata(BEFORE, reverse, AFTER)['make_soong_agree'])

    def test_no_doublecheck_bypass(self):
        with self.assertRaises(ValueError):
            module.validate_metadata(BEFORE, AFTER, BEFORE)

    def test_certificate_change_rejected(self):
        altered = AFTER.replace('testkey.pem', 'other.pem', 1)
        with self.assertRaises(ValueError):
            module.validate_metadata(BEFORE, altered, altered)

    def test_key_path_change_rejected(self):
        altered = AFTER.replace('testkey.pk8', 'other.pk8', 1)
        with self.assertRaises(ValueError):
            module.validate_metadata(BEFORE, altered, altered)

    def test_unrelated_partition_change_rejected(self):
        altered = AFTER.replace('partition="data"', 'partition="system"')
        with self.assertRaises(ValueError):
            module.validate_metadata(BEFORE, altered, altered)

    def test_added_app_rejected(self):
        with self.assertRaises(ValueError):
            module.validate_metadata(BEFORE, AFTER + line('Extra'), AFTER + line('Extra'))

    def test_missing_selected_app_rejected(self):
        with self.assertRaises(ValueError):
            module.validate_metadata(BEFORE.replace(line('webview'), ''), AFTER, AFTER)

    def test_duplicate_selected_app_rejected(self):
        with self.assertRaises(ValueError):
            module.validate_metadata(BEFORE + line('webview'), AFTER, AFTER)

    def test_empty_is_not_success(self):
        with self.assertRaises(ValueError):
            module.validate_metadata('', '', '')

    def test_duplicate_field_rejected(self):
        with self.assertRaises(ValueError):
            module.records(line('webview').rstrip() + ' partition="system"')

    def test_missing_field_rejected(self):
        with self.assertRaises(ValueError):
            module.records('name="webview.apk" partition="system"')


class Layout(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='app-layout-test-')
        self.addCleanup(self.temp.cleanup)
        self.top = Path(self.temp.name) / 'top'
        self.saved = Path(self.temp.name) / 'saved'
        self.saved.mkdir()
        (self.saved / 'before-soong-apkcerts.txt').write_text(BEFORE)
        self.product = self.top / 'out/target/product/gta3xlwifi'
        metadata = self.product / 'obj/PACKAGING/apkcerts_intermediates'
        metadata.mkdir(parents=True)
        for suffix in ('soong_apkcerts_file_with_soong_and_make_modules_removed.txt',
                       'soong-doublecheck.txt'):
            (metadata / (module.PREFIX + suffix)).write_text(AFTER)
        for app in module.APPS:
            path = self.product / 'system/app' / app / (app + '.apk')
            path.parent.mkdir(parents=True)
            path.write_bytes(b'fixture, not an actual APK')

    def test_layout(self):
        self.assertTrue(module.check(self.top, self.saved, False)['passed'])

    def test_missing_actual_apk_rejected(self):
        (self.product / 'system/app/webview/webview.apk').unlink()
        with self.assertRaises(ValueError):
            module.check(self.top, self.saved, False)

    def test_stale_product_apk_rejected(self):
        path = self.product / 'product/app/old/webview.apk'
        path.parent.mkdir(parents=True)
        path.write_bytes(b'stale fixture')
        with self.assertRaises(ValueError):
            module.check(self.top, self.saved, False)

    def test_existing_report_not_overwritten(self):
        report = Path(self.temp.name) / 'report.json'
        report.write_text('preserve')
        result = subprocess.run([sys.executable, str(TOOL), '--top', str(self.top),
                                 '--saved', str(self.saved), '--output', str(report)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
