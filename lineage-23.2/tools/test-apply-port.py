#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise patch replay safety with real temporary Git repositories."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('apply_port', Path(__file__).with_name('apply-port.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.top = self.root / 'top'
        self.repo = self.top / 'project'
        self.repo.mkdir(parents=True)
        self.git('init', '-q')
        (self.repo / 'file').write_text('before\n')
        self.git('add', 'file')
        self.git('-c', 'user.name=Port test', '-c', 'user.email=test@example.invalid',
                 'commit', '-qm', 'base')
        self.revision = self.git('rev-parse', 'HEAD').decode().strip()
        (self.repo / 'file').write_text('after\n')
        patch = self.git('diff', '--binary', '--no-ext-diff', 'HEAD')
        (self.repo / 'file').write_text('before\n')
        self.snapshot = self.root / 'snapshot'
        (self.snapshot / 'patches').mkdir(parents=True)
        (self.snapshot / 'patches/project.patch').write_bytes(patch)
        self.entry = dict(project='project', revision=self.revision, patch='project.patch',
                          sha256=hashlib.sha256(patch).hexdigest())
        self.save_lock()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args])

    def save_lock(self):
        (self.snapshot / 'source-lock.json').write_text(json.dumps([self.entry]))

    def apply(self):
        with contextlib.redirect_stdout(io.StringIO()):
            module.apply(self.top, self.snapshot)

    def test_apply_and_idempotence(self):
        self.apply()
        self.apply()
        self.assertEqual((self.repo / 'file').read_text(), 'after\n')

    def test_local_edits_preserved(self):
        (self.repo / 'file').write_text('owner edits\n')
        with self.assertRaisesRegex(ValueError, 'local modifications'):
            self.apply()
        self.assertEqual((self.repo / 'file').read_text(), 'owner edits\n')

    def test_untracked_files_refused(self):
        (self.repo / 'unreviewed').write_text('keep')
        with self.assertRaisesRegex(ValueError, 'Untracked'):
            self.apply()

    def test_wrong_revision(self):
        self.entry['revision'] = '0' * 40
        self.save_lock()
        with self.assertRaisesRegex(ValueError, 'revision'):
            self.apply()

    def test_corrupt_patch(self):
        (self.snapshot / 'patches/project.patch').write_text('corrupted')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.apply()

    def test_path_escape(self):
        self.entry['project'] = '../outside'
        self.save_lock()
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            self.apply()

    def test_duplicate_project(self):
        (self.snapshot / 'source-lock.json').write_text(json.dumps([self.entry, self.entry]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.apply()
        self.assertEqual((self.repo / 'file').read_text(), 'before\n')


if __name__ == '__main__':
    unittest.main()
