#!/usr/bin/env python3
"""Generate and inspect real vendor block updates without accessing a device."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import zipfile

ROOT = Path('/srv/android')
BASE = ROOT/'src/lineage-21.0'
TOP = ROOT/'src/lineage-21.0-arm64'
sys.path.insert(0, str(BASE/'build/make/tools/releasetools'))
os.environ['PATH'] = str(BASE/'out/host/linux-x86/bin') + ':' + os.environ['PATH']
import common
import edify_generator

spec = importlib.util.spec_from_file_location('arm64_device_hooks', TOP/'device/samsung/gta3xlwifi/releasetools.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
old_targets = BASE/'out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip'
with zipfile.ZipFile(old_targets) as archive:
    info_dict = common.LoadInfoDict(archive)
common.OPTIONS.info_dict = info_dict
common.OPTIONS.source_info_dict = None
common.OPTIONS.worker_threads = 4
common.OPTIONS.cache_size = 159383552
vendor = ROOT/'artifacts/lineage-21-arm64/vendor-hybrid-arm64.img'
target_archive = types.SimpleNamespace(read=lambda name: vendor.read_bytes() if name == 'IMAGES/vendor.img' else None)
report = {'physical_device_accessed': False}
try:
    with tempfile.TemporaryDirectory(prefix='arm64-vendor-ota-') as directory:
        temp = Path(directory)
        target = temp/'target'; source = temp/'source'
        for path in (target, source): (path/'IMAGES').mkdir(parents=True)
        (target/'IMAGES/vendor.img').symlink_to(vendor)
        (source/'IMAGES/vendor.img').symlink_to(ROOT/'vendor-stock/images/vendor.img')
        bad = types.SimpleNamespace(read=lambda name: b'incorrect firmware')
        try:
            module._hybrid_vendor(bad, str(target))
        except ValueError:
            report['unreviewed_vendor_rejected'] = True
        else:
            raise AssertionError('Unreviewed vendor accepted')
        for kind in ('full', 'incremental'):
            if kind == 'full':
                args = types.SimpleNamespace(input_zip=target_archive, input_tmp=str(target))
                differences = module.FullOTA_GetBlockDifferences(args)
            else:
                common.OPTIONS.source_info_dict = info_dict
                args = types.SimpleNamespace(target_zip=target_archive, target_tmp=str(target), source_tmp=str(source))
                differences = module.IncrementalOTA_GetBlockDifferences(args)
            assert len(differences) == 1 and differences[0].partition == 'vendor'
            script = edify_generator.EdifyGenerator(3, info_dict)
            archive_path = temp/(kind+'.zip')
            with zipfile.ZipFile(archive_path, 'w') as archive:
                differences[0].WriteScript(script, archive, progress=0.1, write_verify_script=True)
            with zipfile.ZipFile(archive_path) as archive:
                names = archive.namelist()
                assert 'vendor.transfer.list' in names and 'vendor.patch.dat' in names
                assert ('vendor.new.dat.br' if kind == 'full' else 'vendor.new.dat') in names
            text = '\n'.join(script.script)
            assert 'block_image_update' in text and '/by-name/vendor' in text
            assert 'range_sha1' in text
            assert all('/by-name/'+p not in text for p in ('efs','userdata','recovery','boot'))
            report[kind] = {'standard_vendor_block_update': True, 'post_write_verification': True, 'package_bytes': archive_path.stat().st_size, 'required_cache_bytes': differences[0].required_cache}
    output = ROOT/'artifacts/lineage-21-arm64/vendor-ota-hook-tests.json'
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
finally:
    common.Cleanup()
