#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check profile startup, audio routing and ARM32 ABI in actual signed images."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('target_files', type=Path)
p.add_argument('--report', type=Path, required=True)
p.add_argument('--abi-report', type=Path, required=True)
p.add_argument('--top', type=Path, default=Path('/srv/android/src/lineage-21.0-arm64'))
a = p.parse_args()
abi = json.loads(a.abi_report.read_text())
assert abi['passed'] and not abi['unresolved_symbols']
host = a.top / 'out/host/linux-x86/bin'
digest = lambda b: hashlib.sha256(b).hexdigest()
enabled = ('a2dp.source', 'avrcp.target', 'bas.client', 'gatt', 'hid.host', 'opp',
           'pan.nap', 'pan.panu')
disabled = ('bap.broadcast.assist', 'bap.broadcast.source', 'bap.unicast.client',
            'bass.client', 'ccp.server', 'csip.set_coordinator', 'hap.client',
            'hfp.ag', 'mcp.server', 'vcp.controller')
with zipfile.ZipFile(a.target_files) as z, tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)
    values = {}
    property_files = [name for name in z.namelist()
                      if name.endswith('/build.prop')
                      and name.startswith(('SYSTEM/', 'SYSTEM_EXT/', 'PRODUCT/'))]
    for name in property_files:
        for line in z.read(name).decode().splitlines():
            if line.startswith('bluetooth.profile.'):
                key, value = line.split('=', 1)
                values.setdefault(key, []).append(value)
    for suffixes, value in ((enabled, 'true'), (disabled, 'false')):
        for suffix in suffixes:
            key = 'bluetooth.profile.' + suffix + '.enabled'
            assert values.get(key) == [value], (
                f'{suffix} property absent, duplicate or conflicting: {values.get(key)!r}')
    sparse, raw = d/'vendor.img', d/'vendor.raw.img'
    with z.open('IMAGES/vendor.img') as src, sparse.open('wb') as dst:
        shutil.copyfileobj(src, dst)
    subprocess.run([str(host/'simg2img'), str(sparse), str(raw)], check=True)

    def read_image(image, path):
        result = subprocess.run([str(host/'debugfs_static'), '-R', 'cat /'+path,
                                 str(image)], capture_output=True, check=True)
        assert result.stdout, path
        return result.stdout

    module_bytes = read_image(raw, 'lib/hw/audio.bluetooth.exynos7904.so')
    assert digest(module_bytes) == abi['shim_sha256'], 'Different Bluetooth audio module'
    main = ET.fromstring(read_image(raw, 'etc/audio_policy_configuration.xml'))
    includes = [n.get('href') for n in main.iter()
                if n.tag == '{http://www.w3.org/2001/XInclude}include']
    assert includes.count('bluetooth_audio_policy_configuration.xml') == 1
    assert 'a2dp_audio_policy_configuration.xml' not in includes
    policy = ET.fromstring(read_image(raw, 'etc/bluetooth_audio_policy_configuration.xml'))
    assert policy.get('name') == 'bluetooth' and policy.get('halVersion') == '2.0'
    assert any(n.get('type') == 'AUDIO_DEVICE_OUT_BLUETOOTH_A2DP' for n in policy.iter())
    manifest = ET.fromstring(read_image(raw, 'etc/vintf/manifest/gta3xlwifi_btaudio.xml'))
    hal = manifest.find('hal')
    assert hal.findtext('name') == 'android.hardware.bluetooth.audio'
    assert hal.findtext('transport') == 'hwbinder' and hal.findtext('version') == '2.0'
    assert hal.findtext('interface/name') == 'IBluetoothAudioProvidersFactory'
    assert hal.findtext('interface/instance') == 'default'

    # Recheck the module against the providers from the signed package, rather
    # than trusting the compiler output's library search paths.
    virtual = d/'signed-providers'
    virtual.mkdir()
    apexes = {}

    def apex_file(apex, path):
        if apex not in apexes:
            matches = [n for n in z.namelist()
                       if n.endswith(('/'+apex+'.apex', '/'+apex+'.capex'))]
            assert len(matches) == 1, (apex, matches)
            package = zipfile.ZipFile(io.BytesIO(z.read(matches[0])))
            if 'original_apex' in package.namelist():
                package = zipfile.ZipFile(io.BytesIO(package.read('original_apex')))
            image = d/(apex+'.img')
            image.write_bytes(package.read('apex_payload.img'))
            apexes[apex] = image
        return read_image(apexes[apex], path)

    for name, original in abi['needed'].items():
        vndk = next((kind for kind in ('vndk-sp', 'vndk-core')
                     if '/'+kind+'/' in original), None)
        if vndk:
            target = virtual/'prebuilts/vndk/v30/arm64/arch-arm-armv8-a/shared'/vndk/name
            data = apex_file('com.android.vndk.v30', 'lib/'+name)
        elif name in ('libc.so', 'libm.so', 'libdl.so'):
            target = virtual/'out/target/product/gta3xlwifi/apex/com.android.runtime/lib/bionic'/name
            data = apex_file('com.android.runtime', 'lib/bionic/'+name)
        else:
            target = virtual/'out/target/product/gta3xlwifi/system/lib'/name
            data = z.read('SYSTEM/lib/'+name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    module = d/'audio.bluetooth.exynos7904.so'
    module.write_bytes(module_bytes)
    signed_abi = d/'signed-abi.json'
    subprocess.run(['python3', str(Path(__file__).with_name('check-btaudio-shim-abi.py')),
                    str(module), str(signed_abi), '--top', str(virtual)], check=True)
    actual = json.loads(signed_abi.read_text())
    assert actual['passed']
    props = dict(line.split('=', 1) for line in z.read('SYSTEM/build.prop').decode().splitlines()
                 if '=' in line and not line.startswith('#'))
    report = {'passed': True, 'build_incremental': props['ro.build.version.incremental'],
              'profile_properties_verified': values, 'profile_property_files': property_files,
              'vendor_sparse_sha256': digest(sparse.read_bytes()),
              'audio_module_sha256': digest(module_bytes), 'hidl_2_0_factory_declared': True,
              'bluetooth_audio_policy_selected': True, 'signed_provider_abi_passed': True,
              'signed_provider_sha256': actual['needed_sha256'], 'hardware_tested': False}
    a.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
