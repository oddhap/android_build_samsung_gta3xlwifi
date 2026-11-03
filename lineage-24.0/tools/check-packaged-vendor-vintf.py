#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline VINTF check: packaged framework/APEX plus actual extracted vendor.

AOSP apexd_host simulates factory APEX extraction/inventory. Its isActive fields
are host simulation, NOT evidence of live activation, kernel mounts or readiness.
No TOP, original vendor, source image, partition or device is modified.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import xml.etree.ElementTree as ET
import zipfile


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['top', 'archive', 'vendor', 'kernel-config', 'output']:
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--expected-archive-sha256', required=True)
    args = parser.parse_args()
    top, archive, vendor, kernel, output = [p.resolve() for p in
        [args.top, args.archive, args.vendor, args.kernel_config, args.output]]
    if output.is_relative_to(top) or output.is_relative_to(vendor) or output.exists():
        raise ValueError('Output must be fresh and outside protected TOP/vendor')
    archive_sha = digest(archive)
    if archive_sha != args.expected_archive_sha256:
        raise ValueError('Archive identity mismatch')
    host = top/'out/host/linux-x86'
    tools = {name:host/'bin'/name for name in
             ['apexd_host', 'deapexer', 'debugfs_static', 'fsck.erofs', 'checkvintf']}
    tool_hashes = {name:digest(p) for name,p in tools.items()}
    output.mkdir(parents=True, exist_ok=False)
    stage = output/'factory'
    apex = output/'apex'
    apex.mkdir()
    for part in ['system', 'system_ext', 'product', 'odm']:
        (stage/part).mkdir(parents=True)
    # Most-specific nested partition first. Do NOT substitute generated VENDOR/
    # contents for the actual prebuilt vendor used by this hybrid product.
    prefixes = [('SYSTEM/system_ext/', 'system_ext'), ('SYSTEM_EXT/', 'system_ext'),
                ('SYSTEM/', 'system'), ('PRODUCT/', 'product')]
    copied, packages, seen = [], [], set()
    with zipfile.ZipFile(archive) as z:
        if len(z.namelist()) != len(set(z.namelist())):
            raise ValueError('Duplicate archive entries')
        for item in z.infolist():
            if item.is_dir():
                continue
            selected = None
            for prefix, part in prefixes:
                if item.filename.startswith(prefix):
                    rel = item.filename[len(prefix):]
                    if (rel.startswith('etc/vintf/') and rel.endswith('.xml')) or (
                            rel.startswith('apex/') and len(PurePosixPath(rel).parts)==2
                            and rel.endswith(('.apex', '.capex'))):
                        selected = part, rel
                    break
            if selected is None:
                continue
            part, rel = selected
            path = PurePosixPath(rel)
            if path.is_absolute() or '..' in path.parts or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Unsafe selected archive entry')
            dest = stage/part/rel
            if str(dest) in seen:
                raise ValueError('Aliased partition destination')
            seen.add(str(dest))
            dest.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            with z.open(item) as src, dest.open('xb') as dst:
                for block in iter(lambda:src.read(1024*1024),b''):
                    dst.write(block)
                    h.update(block)
            copied.append({'archive_member':item.filename, 'sha256':h.hexdigest(),
                           'partition':part, 'staged':str(dest)})
            if rel.endswith(('.apex','.capex')):
                packages.append(dest)
    if not packages or not (stage/'system/etc/vintf/manifest.xml').is_file():
        raise ValueError('Missing real packaged framework/APEX inputs')
    # Factory vendor may also contain APEX files; account for those too.
    vendor_packages = sorted((vendor/'apex').glob('*.apex')) + sorted((vendor/'apex').glob('*.capex'))
    command = [str(tools['apexd_host']), '--tool_path', str(host), '--apex_path', str(apex),
               '--system_path', str(stage/'system'), '--system_ext_path', str(stage/'system_ext'),
               '--product_path', str(stage/'product'), '--vendor_path', str(vendor),
               '--odm_path', str(stage/'odm')]
    with (output/'apexd-host.log').open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    inventory = apex/'apex-info-list.xml'
    entries = list(ET.parse(inventory).getroot().iter('apex-info'))
    if len(entries) != len(packages)+len(vendor_packages):
        raise ValueError('Host simulation skipped/aliased a factory APEX')
    modules = [e.get('moduleName') for e in entries]
    if len(modules) != len(set(modules)) or 'com.android.vndk.v30' not in modules:
        raise ValueError('Missing/ambiguous actual VNDK30 package')
    check = [str(tools['checkvintf']), '--check-compat']
    partitions = {'system':stage/'system', 'system_ext':stage/'system_ext',
                  'product':stage/'product', 'vendor':vendor, 'odm':stage/'odm', 'apex':apex}
    for part, path in partitions.items():
        check += ['--dirmap', f'/{part}:{path}']
    check += ['--property','ro.product.first_api_level=28',
              '--property','ro.boot.product.hardware.sku=',
              '--property','ro.boot.product.vendor.sku=', '--kernel',f'4.4.302:{kernel}']
    run = subprocess.run(check, text=True, capture_output=True)
    (output/'checkvintf.log').write_text(run.stdout+run.stderr)
    if any(digest(tools[n]) != h for n,h in tool_hashes.items()):
        raise ValueError('Host tool changed during the check')
    metadata = {kernel, inventory}
    for root in partitions.values():
        metadata.update(p for p in (root/'etc/vintf').rglob('*') if p.is_file())
    metadata.update(p for p in apex.rglob('*.xml') if p.is_file() and 'etc/vintf/' in str(p))
    result = {'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope':'Offline factory APEX simulation and actual-vendor VINTF metadata only',
              'archive':str(archive), 'archive_sha256':archive_sha,
              'factory_inputs':copied,
              'vendor_apex_inputs':[{'path':str(p),'sha256':digest(p)} for p in vendor_packages],
              'host_tools_sha256':tool_hashes, 'apexd_host_command':command,
              'checkvintf_command':check, 'exit_code':run.returncode,
              'offline_metadata_passed':run.returncode==0,
              'factory_apex_count':len(entries), 'modules':modules,
              'metadata_inputs':[{'path':str(p),'sha256':digest(p)} for p in sorted(metadata)],
              'inventory_origin':'AOSP apexd_host simulation of real factory packages',
              'live_apex_activation_proven':False, 'kernel_mounts_or_policy_proven':False,
              'runtime_or_HALS_validated':False, 'hardware_tested':False,
              'flash_ready':False, 'original_sources_images_or_device_modified':False}
    (output/'report.json').write_text(json.dumps(result,indent=2)+'\n')
    print('\n'.join((run.stdout+run.stderr).splitlines()[-18:]))
    print(f'Offline factory APEX count: {len(entries)}; VINTF exit: {run.returncode}')
    return 0 if run.returncode==0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
