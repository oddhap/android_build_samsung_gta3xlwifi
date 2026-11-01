#!/usr/bin/env python3
"""Exercise real configurators in a temporary source layout, without signing."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PORT = Path(__file__).resolve().parents[2]
BASELINE = '276777b5bde1dac2f31dbe9299c79e02c07486df6ff7b2ecad03cc722edee939'

class VendorConfigurationTest(unittest.TestCase):
    def test_reconfigure_existing_arm64_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            port = root/'ports/lineage-21-arm64/lineage-21'
            shutil.copytree(PORT/'lineage-21/tools', port/'tools')
            shutil.copytree(PORT/'lineage-21/notes', port/'notes')
            # Recreate the reviewed October baseline even when this test is
            # run from a later release whose published hash has advanced.
            lock_path = port/'notes/source-inputs.lock.json'
            initial_lock = json.loads(lock_path.read_text())
            current_sha = initial_lock['inputs']['vendor_sha256']
            initial_lock['inputs']['vendor_sha256'] = BASELINE
            lock_path.write_text(json.dumps(initial_lock))
            for tool in ('sign-release.py', 'verify-native-images.py'):
                tool_path = port/'tools'/tool
                tool_path.write_text(tool_path.read_text().replace(current_sha, BASELINE))
            device = root/'src/lineage-21.0-arm64/device/samsung/gta3xlwifi'
            (device/'prebuilt').mkdir(parents=True)
            # Immutable fixture from device commit 9103cae139f954cccb5d9b01808787571db3189e.
            hooks = Path(__file__).parent/'fixtures/releasetools-arm64-20261015.py'
            shutil.copy2(hooks, device/'releasetools.py')
            before_hooks = (device/'releasetools.py').read_text()
            vendor = b'isolated vendor guard fixture; not an installable image'
            new_sha = hashlib.sha256(vendor).hexdigest()
            (device/'prebuilt/vendor.img').write_bytes(vendor)
            (device/'prebuilt/provenance.json').write_text(json.dumps({'vendor_sha256': new_sha}))
            report = root/'vendor-report.json'
            report.write_text(json.dumps({'sparse_sha256': new_sha}))

            def run(script, *args):
                # Only redirect the fixed workstation root; execute the actual
                # script's remaining code and filesystem transformations.
                source = (PORT/script).read_text().replace(
                    "ROOT = Path('/srv/android')", f'ROOT = Path({str(root)!r})')
                runner = root/script
                runner.write_text(source)
                return subprocess.run([sys.executable, str(runner), *args],
                                      capture_output=True, text=True)

            configured = run('configure-arm64-release.py')
            self.assertEqual(configured.returncode, 0, configured.stderr)
            after_hooks = (device/'releasetools.py').read_text()
            self.assertEqual(after_hooks, before_hooks.replace(BASELINE, new_sha))
            signer = (port/'tools/sign-release.py').read_text()
            self.assertIn(f"hashlib.sha256(vendor_before).hexdigest() != '{new_sha}'", signer)
            self.assertNotIn(BASELINE, signer)
            verified = run('configure-arm64-verifiers.py', '--vendor-report', str(report))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            lock = json.loads((port/'notes/source-inputs.lock.json').read_text())
            self.assertEqual(lock['inputs']['vendor_sha256'], new_sha)
            self.assertIn(new_sha, (port/'tools/verify-native-images.py').read_text())
            self.assertNotIn(BASELINE, (port/'tools/verify-native-images.py').read_text())
            # Repeated configuration retains identical guards.
            repeated = run('configure-arm64-release.py')
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            self.assertEqual((device/'releasetools.py').read_text(), after_hooks)
            (device/'prebuilt/vendor.img').write_bytes(b'tampered image')
            rejected = run('configure-arm64-release.py')
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('differs from its audited provenance', rejected.stderr)
            self.assertEqual((device/'releasetools.py').read_text(), after_hooks)

if __name__ == '__main__':
    unittest.main()
