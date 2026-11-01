#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic metadata safety/invariant tests, NOT actual policy or hardware tests."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('uwb_stage', Path(__file__).with_name('stage-vendor-uwb-namespace.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NamespaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='vendor-uwb-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.top, self.vendor, self.output = self.root/'top', self.root/'vendor', self.root/'result'
        self.top.mkdir()
        self.source = self.vendor/'etc/selinux'
        self.source.mkdir(parents=True)
        self.cil = ('; preserve uwb_service and hal_uwb_service in comments\n'
                    '(type uwb_service)\n(type hal_uwb_service)\n(type uwb_service_extra)\n'
                    '(allow app uwb_service (service_manager (find)))\n'
                    '(neverallow other uwb_service (service_manager (add)))\n'
                    '(typeattributeset services (hal_uwb_service uwb_service))\n'
                    '(filecon "/uwb_service/hal_uwb_service" any (u r uwb_service ((s0) (s0))))\n')
        for name in module.FILES:
            (self.source/name).write_text('' if name.endswith('contexts') else '; fixture\n')
        (self.source/'vendor_sepolicy.cil').write_text(self.cil)
        (self.source/'plat_pub_versioned.cil').write_text('(type uwb_service_30_0)\n')
        (self.source/'plat_sepolicy_vers.txt').write_text('30.0\n')
        (self.source/'vendor_service_contexts').write_text(
            module.ENDPOINT + '\t u:object_r:hal_uwb_service:s0 # keep hal_uwb_service comment\n')
        (self.source/'precompiled_sepolicy').write_bytes(b'\0BINARY MUST NOT BE COPIED')
        (self.source/'sk').mkdir()
        (self.source/'sk/sentinel').write_text('DO NOT READ/COPY')

    def stage(self, checksum=None):
        if checksum is None:
            checksum = hashlib.sha256((self.source/'vendor_sepolicy.cil').read_bytes()).hexdigest()
        return module.stage(self.top, self.vendor, self.output, checksum)

    def reject(self):
        with self.assertRaises((ValueError, FileNotFoundError, FileExistsError)):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_exact_alpha_rename_only_two_files_and_rules_unchanged(self):
        before = {n: (self.source/n).read_bytes() for n in module.FILES}
        r = self.stage()
        self.assertEqual(r['changed_files'], ['vendor_sepolicy.cil', 'vendor_service_contexts'])
        self.assertEqual(r['rule_counts_before'], r['rule_counts_after'])
        self.assertEqual(r['rule_counts_after'], {'allow': 1, 'neverallow': 1})
        text = (self.output/'vendor/etc/selinux/vendor_sepolicy.cil').read_text()
        self.assertIn('; preserve uwb_service and hal_uwb_service in comments', text)
        self.assertIn('"/uwb_service/hal_uwb_service"', text)
        self.assertIn('(type uwb_service_extra)', text)
        self.assertIn('(type vendor_samsung_legacy_uwb_service)', text)
        self.assertEqual({n: (self.source/n).read_bytes() for n in module.FILES}, before)
        self.assertFalse((self.output/'vendor/etc/selinux/precompiled_sepolicy').exists())
        self.assertFalse((self.output/'vendor/etc/selinux/sk').exists())
        self.assertFalse(r['security_approved'])
        self.assertFalse(r['flash_ready'])
        json.loads((self.output/'report.json').read_text())

    def test_wrong_checksum_rejected(self):
        with self.assertRaises(ValueError): self.stage('0'*64)
        self.assertFalse(self.output.exists())

    def test_unexpected_version_rejected(self):
        (self.source/'plat_sepolicy_vers.txt').write_text('31.0\n')
        self.reject()

    def test_existing_output_sentinel_preserved(self):
        self.output.mkdir()
        (self.output/'report.json').write_text('KEEP')
        with self.assertRaises(FileExistsError): self.stage()
        self.assertEqual((self.output/'report.json').read_text(), 'KEEP')

    def test_protected_source_vendor_and_alias_output(self):
        for base in [self.top, self.vendor]:
            self.output = base/'no-write'
            self.reject()
        alias = self.root/'alias'
        alias.symlink_to(self.vendor, target_is_directory=True)
        self.output = alias/'no-write'
        self.reject()

    def test_nonregular_input_rejected(self):
        p = self.source/'vendor_file_contexts'
        p.unlink()
        p.mkdir()
        self.reject()

    def test_source_symlink_rejected(self):
        p = self.source/'vendor_sepolicy.cil'
        data = p.read_bytes()
        outside = self.root/'outside'
        outside.write_bytes(data)
        p.unlink()
        p.symlink_to(outside)
        self.reject()

    def test_public_symbol_rejected(self):
        for name in ['uwb_service', 'vendor_samsung_legacy_uwb_service']:
            (self.source/'plat_pub_versioned.cil').write_text('(type ' + name + ')\n')
            self.reject()

    def test_odm_policy_cannot_be_silently_omitted(self):
        p = self.vendor/'odm/etc/selinux/odm_sepolicy.cil'
        p.parent.mkdir(parents=True)
        p.write_text('; unreviewed fixture\n')
        self.reject()

    def test_destination_collision_rejected(self):
        with (self.source/'vendor_sepolicy.cil').open('a') as f:
            f.write('(type vendor_samsung_legacy_uwb_service)\n')
        self.reject()

    def test_missing_or_duplicate_private_declaration_rejected(self):
        for tail in ['', '(type uwb_service)\n']:
            (self.source/'vendor_sepolicy.cil').write_text(
                self.cil.replace('(type uwb_service)\n', '') + tail*2)
            self.reject()

    def test_bad_cil_lexical_forms_rejected(self):
        for text in [self.cil+'\0', self.cil+')', self.cil+'(', self.cil+'"unterminated']:
            (self.source/'vendor_sepolicy.cil').write_text(text)
            self.reject()

    def test_quoted_private_identifier_rejected(self):
        with (self.source/'vendor_sepolicy.cil').open('a') as f:
            f.write('(roletype object_r "uwb_service")\n')
        self.reject()

    def test_unknown_seapp_type_reference_rejected(self):
        (self.source/'vendor_seapp_contexts').write_text('user=_app type=uwb_service\n')
        self.reject()

    def test_unknown_context_reference_rejected(self):
        (self.source/'vendor_hwservice_contexts').write_text('unknown u:object_r:uwb_service:s0\n')
        self.reject()

    def test_wrong_or_duplicate_endpoint_rejected(self):
        p = self.source/'vendor_service_contexts'
        original = p.read_text()
        for text in [original.replace('hal_uwb_service:s0', 'other:s0'), original*2, '']:
            p.write_text(text)
            self.reject()

    def test_missing_required_input_rejected(self):
        (self.source/'vendor_file_contexts').unlink()
        self.reject()

    def test_escaped_strings_and_comment_braces_do_not_change_syntax(self):
        text = '(type uwb_service) ; ) not syntax\n(filecon "quoted\\\"uwb_service" any x)\n'
        result, counts = module.rewrite_cil(text, module.RENAMES)
        self.assertEqual(counts, {'uwb_service': 1})
        self.assertIn('"quoted\\\"uwb_service"', result)
        inverse, _ = module.rewrite_cil(result, {v:k for k,v in module.RENAMES.items()})
        self.assertEqual(inverse, text)


if __name__ == '__main__':
    unittest.main()
