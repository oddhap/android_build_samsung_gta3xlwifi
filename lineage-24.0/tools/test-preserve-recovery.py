#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual recovery-patch function bodies and scoped Make metadata.

Image contents, fstab lookup and binary diffing are fixtures. No images, keys,
devices or partitions are read/written by the extracted function fixtures.
"""
import argparse
import ast
import logging
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--before', required=True, type=Path)
parser.add_argument('--after', required=True, type=Path)
parser.add_argument('--makefile', required=True, type=Path)
parser.add_argument('--non-ab-source', required=True, type=Path)
args, remaining = parser.parse_known_args()


class ExternalError(Exception):
    pass


class Difference:
    def __init__(self, *unused):
        pass

    def ComputePatch(self):
        return None, None, b'fixture-binary-patch'


def get_type_device(path, info, **unused):
    if info.get('missing_fstab'):
        raise KeyError(path)
    return 'EMMC', '/fixture/'+path.lstrip('/')


def load(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name=='MakeRecoveryPatch']
    assert len(functions)==1
    env = {'logger':logging.getLogger('fixture'), 'ExternalError':ExternalError,
           'OPTIONS':SimpleNamespace(info_dict={}), 'Difference':Difference,
           'GetTypeAndDevice':get_type_device, 'os':os}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec'), env)
    return env['MakeRecoveryPatch']


before, after = load(args.before), load(args.after)
recovery = SimpleNamespace(data=b'recovery-bytes', sha1='recovery-hash', size=14)
boot = SimpleNamespace(data=b'boot-bytes', sha1='boot-hash', size=10)


def run(function, info, image=recovery):
    output = []
    function('/fixture', lambda name,data:output.append((name,data)), image, boot, info_dict=info)
    return output


class PreservationTests(unittest.TestCase):
    def test_preserved_recovery_reads_no_image_and_emits_nothing(self):
        class UnreadableImage:
            @property
            def data(self):
                raise AssertionError('Recovery data must not be consumed')
        self.assertEqual(run(after, {'gta3xlwifi_preserve_recovery':'true',
                                    'allow_non_ab':'true'}, UnreadableImage()), [])

    def test_invalid_preservation_contract_rejected(self):
        for extra in [{'ab_update':'true'}, {'allow_non_ab':'false'},
                      {'multistage_support':'1'}, {'multistage_support':'0'}]:
            with self.subTest(extra=extra), self.assertRaises(ExternalError):
                run(after, {'gta3xlwifi_preserve_recovery':'true', 'allow_non_ab':'true', **extra})
        with self.assertRaises(ExternalError):
            run(after, {'gta3xlwifi_preserve_recovery':'true'})

    def test_generic_products_preserve_exact_generator_outputs(self):
        for full in ['true','false']:
            for vendor in ['true','false']:
                for missing in [False,True]:
                    info = {'full_recovery_image':full, 'board_uses_vendorimage':vendor,
                            'missing_fstab':missing}
                    with self.subTest(info=info):
                        self.assertEqual(run(after,info),run(before,info))

    def test_make_metadata_is_scoped_and_disables_multistage(self):
        text=args.makefile.read_text()
        block=re.search(r'^# Preserve the installed SM-T510 TWRP;.*?^endif$',text,re.M|re.S)
        self.assertIsNotNone(block)
        for device, expected in [('gta3xlwifi',{'gta3xlwifi_preserve_recovery':'true'}),
                                 ('other_device',{'multistage_support':'1'})]:
            with self.subTest(device=device), tempfile.TemporaryDirectory(prefix='recovery-make-') as d:
                p=Path(d)
                (p/'fixture.mk').write_text('hide := @\nresult.txt:\n'+block[0]+'\n')
                subprocess.run(['make','--no-print-directory','-f','fixture.mk',
                                'TARGET_DEVICE='+device,'result.txt'], cwd=p,check=True,capture_output=True)
                found=dict(line.split('=',1) for line in (p/'result.txt').read_text().splitlines())
                self.assertEqual(found,expected)

    def test_two_step_rejected_before_full_or_incremental_generation(self):
        tree=ast.parse(args.non_ab_source.read_text())
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='GenerateNonAbOtaPackage')
        for flag,two_step,message in [('true',True,'preserved recovery'),
                                      ('true',False,'no recovery'),
                                      ('false',True,'no recovery')]:
            options=SimpleNamespace(info_dict={'gta3xlwifi_preserve_recovery':flag,
                                              'no_recovery':'true'},two_step=two_step)
            env={'OPTIONS':options,'common':SimpleNamespace(ExternalError=ExternalError)}
            exec(compile(ast.Module(body=[function],type_ignores=[]),str(args.non_ab_source),'exec'),env)
            for source in [None,'fixture-source-for-incremental']:
                with self.subTest(flag=flag,two_step=two_step,source=source), self.assertRaisesRegex(ExternalError,message):
                    env['GenerateNonAbOtaPackage']('fixture-target','fixture-output',source_file=source)


if __name__ == '__main__':
    unittest.main(argv=['test-preserve-recovery.py', *remaining])
