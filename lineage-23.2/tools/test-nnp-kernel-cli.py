#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Safety rejections only; does not fabricate successful ELF/kernel proof."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).with_name('check-nnp-transition-kernel.py')


class Safety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='nnp-cli-')
        self.root = Path(self.tmp.name).resolve()
        for n in ['src', 'out', 'experiment', 'owned', 'protected']:
            (self.root/n).mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def reject(self, output):
        before = sorted(str(x.relative_to(self.root)) for x in self.root.rglob('*'))
        command = [sys.executable, str(TOOL), '--nm', '/missing/nm',
            '--objdump', '/missing/objdump', '--objcopy', '/missing/objcopy',
            '--protected', str(self.root/'protected'), str(self.root/'src'),
            str(self.root/'out'), str(self.root/'Image'), str(self.root/'experiment'),
            str(self.root/'owned'), str(output)]
        for mode in [[], ['--functionfs']]:
            r = subprocess.run(command + mode, capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertEqual(before, sorted(str(x.relative_to(self.root)) for x in self.root.rglob('*')))

    def test_source_descendant(self):
        self.reject(self.root/'src/new')

    def test_kernel_output_descendant(self):
        self.reject(self.root/'out/new')

    def test_exact_source(self):
        self.reject(self.root/'src')

    def test_experiment_descendant(self):
        self.reject(self.root/'experiment/new')

    def test_explicit_protected_descendant(self):
        self.reject(self.root/'protected/new')

    def test_resolved_protected_alias(self):
        (self.root/'alias').symlink_to(self.root/'protected', target_is_directory=True)
        self.reject(self.root/'alias/new')

    def test_existing_output_directory(self):
        (self.root/'scratch').mkdir()
        self.reject(self.root/'scratch')

    def test_existing_output_file(self):
        (self.root/'scratch').write_text('preserve me\n')
        self.reject(self.root/'scratch')
        self.assertEqual((self.root/'scratch').read_text(), 'preserve me\n')


if __name__ == '__main__':
    unittest.main()
