#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check byte-exact snapshot reuse and rejection with real temporary Git repos."""
import contextlib,hashlib,importlib.util,io,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('capture',Path(__file__).with_name('capture-port.py'));capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)
class CaptureTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.top=self.root/'top';self.repo=self.top/'project';self.repo.mkdir(parents=True)
  self.git('init','-q');self.git('config','core.whitespace','blank-at-eof,blank-at-eol,space-before-tab')
  (self.repo/'file').write_text('base\n');self.git('add','file');self.git('-c','user.name=Port test','-c','user.email=test@example.invalid','-c','commit.gpgsign=false','commit','-qm','base')
  self.revision=self.git('rev-parse','HEAD').decode().strip();(self.repo/'file').write_text('frozen\n\n')
  self.parent=self.root/'parent';(self.parent/'patches').mkdir(parents=True);data=self.git('diff','--binary','--no-ext-diff','--full-index','HEAD');(self.parent/'patches/project.patch').write_bytes(data)
  self.row={'project':'project','revision':self.revision,'patch':'project.patch','sha256':hashlib.sha256(data).hexdigest()};self.lock()
  tools=self.root/'bin';tools.mkdir();mock=tools/'repo';mock.write_text('''#!/usr/bin/env python3
import subprocess,sys
from pathlib import Path
assert sys.argv[1:4]==['manifest','-r','-o']
rev=subprocess.check_output(['git','-C','project','rev-parse','HEAD'],text=True).strip()
Path(sys.argv[4]).write_text('<manifest><project name="fixture" path="project" revision="'+rev+'"/></manifest>')
''');mock.chmod(0o755);self.env=patch.dict(os.environ,{'PATH':str(tools)+os.pathsep+os.environ['PATH']});self.env.start();self.addCleanup(self.env.stop)
 def git(self,*args):return subprocess.check_output(['git','-C',str(self.repo),*args])
 def lock(self):(self.parent/'source-lock.json').write_text(json.dumps([self.row]))
 def run_capture(self,parent=True):
  with contextlib.redirect_stdout(io.StringIO()):capture.capture(self.top,self.root/'out',['project'],self.parent if parent else None)
 def test_exact_frozen_patch_reuses_only_identical_bytes(self):
  self.run_capture();r=json.loads((self.root/'out/capture-parent.json').read_text());self.assertEqual(r['byte_exact_style_approvals_reused'],[{'project':'project','sha256':self.row['sha256']}]);self.assertEqual((self.repo/'file').read_text(),'frozen\n\n')
 def test_no_parent_keeps_normal_style_rejection(self):
  with self.assertRaises(subprocess.CalledProcessError):self.run_capture(False)
 def test_changed_bad_patch_cannot_reuse_approval(self):
  (self.repo/'file').write_text('changed\n\n')
  with self.assertRaises(subprocess.CalledProcessError):self.run_capture()
  self.assertEqual((self.repo/'file').read_text(),'changed\n\n')
 def test_changed_clean_patch_uses_normal_style_check(self):
  (self.repo/'file').write_text('changed clean\n');self.run_capture();r=json.loads((self.root/'out/capture-parent.json').read_text());self.assertEqual(r['byte_exact_style_approvals_reused'],[])
 def test_corrupt_parent_is_rejected(self):
  (self.parent/'patches/project.patch').write_text('corrupt')
  with self.assertRaisesRegex(ValueError,'hash mismatch'):self.run_capture()
 def test_wrong_revision_cannot_skip_style_check(self):
  self.row['revision']='0'*40;self.lock()
  with self.assertRaises(subprocess.CalledProcessError):self.run_capture()
 def test_untracked_file_is_still_rejected(self):
  (self.repo/'unreviewed').write_text('owner data')
  with self.assertRaisesRegex(ValueError,'untracked'):self.run_capture()
if __name__=='__main__':unittest.main()
