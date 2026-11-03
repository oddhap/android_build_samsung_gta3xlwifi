#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic OTA metadata fixtures, not actual ROM or hardware validation."""
import importlib.util
import io
from pathlib import Path
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('check_target_files', Path(__file__).with_name('check-target-files.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class LayoutTests(unittest.TestCase):
    def check(self, metadata='allow_non_ab=true\ngta3xlwifi_preserve_recovery=true\n', props=None, extra=None):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as z:
            z.writestr('META/misc_info.txt', metadata)
            for name in extra or []:
                z.writestr(name, '')
        with zipfile.ZipFile(io.BytesIO(data.getvalue())) as z:
            return checker.check_ota_layout(z, props or {})

    def test_real_non_ab_metadata(self):
        self.assertTrue(self.check()['physical_non_ab'])
        self.assertTrue(self.check('ab_update=false\nallow_non_ab=true\ngta3xlwifi_preserve_recovery=true\nvirtual_ab_cow_version=2\n')['physical_non_ab'])

    def test_observed_android17_default_rejected(self):
        with self.assertRaisesRegex(ValueError, 'A/B OTA'):
            self.check('ab_update=true\nvirtual_ab_cow_version=2\n')

    def test_missing_non_ab_support_rejected(self):
        with self.assertRaises(ValueError):
            self.check('ab_update=false\n')

    def test_dynamic_and_virtual_modes_rejected(self):
        for key in ['use_dynamic_partitions', 'virtual_ab', 'virtual_ab_retrofit']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check('allow_non_ab=true\ngta3xlwifi_preserve_recovery=true\n'+key+'=true\n')

    def test_runtime_slot_properties_rejected(self):
        for key in ['ro.build.ab_update', 'ro.virtual_ab.enabled', 'ro.boot.dynamic_partitions']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(props={key:'true'})

    def test_stale_slot_or_dynamic_metadata_rejected(self):
        for name in ['META/ab_partitions.txt', 'META/dynamic_partitions_info.txt']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check(extra=[name])

    def test_missing_preservation_or_multistage_rejected(self):
        with self.assertRaises(ValueError):
            self.check('allow_non_ab=true\n')
        for value in ['0','1']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check('allow_non_ab=true\ngta3xlwifi_preserve_recovery=true\nmultistage_support='+value+'\n')

    def test_recovery_replacement_resources_rejected(self):
        for name in ['VENDOR/etc/recovery.img', 'SYSTEM/vendor/etc/recovery.img',
                     'VENDOR/bin/install-recovery.sh', 'SYSTEM/vendor/recovery-from-boot.p',
                     'SYSTEM/etc/recovery-resource.dat', 'VENDOR/etc/init/vendor_flash_recovery.rc']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check(extra=[name])


if __name__ == '__main__':
    unittest.main()
