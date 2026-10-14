#!/usr/bin/env python3
"""Inspect signed DT2W controls, framework resource and SELinux labels offline."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('target_files', type=Path)
parser.add_argument('--top', type=Path, default=Path('/srv/android/src/lineage-21.0-arm64'))
parser.add_argument('--report', type=Path, required=True)
args = parser.parse_args()
controls = ('/sys/class/sec/tsp/double_tap_to_wake', '/sys/class/sec/tsp/input_enabled')
labels = ('/devices/virtual/sec/tsp/double_tap_to_wake',
          '/devices/virtual/sec/tsp/input_enabled')
report = {'hardware_tested': False, 'native_libraries': {}}
with zipfile.ZipFile(args.target_files) as archive:
    for bits, directory, machine in ((64, 'lib64', 183), (32, 'lib', 40)):
        name = 'SYSTEM/'+directory+'/libandroid_servers.so'
        data = archive.read(name)
        assert data[:5] == b'\x7fELF'+bytes([2 if bits == 64 else 1]), name
        assert struct.unpack_from('<H', data, 18)[0] == machine, name
        assert all(path.encode()+b'\0' in data for path in controls), name
        report['native_libraries'][str(bits)] = hashlib.sha256(data).hexdigest()
    init = archive.read('SYSTEM/system_ext/etc/init/init.gta3xlwifi.power.rc').decode()
    for path in controls:
        assert re.search(r'^\s+chown system system '+re.escape(path)+r'\s*$', init, re.M), path
        assert re.search(r'^\s+chmod 0660 '+re.escape(path)+r'\s*$', init, re.M), path
    policy = archive.read('SYSTEM/system_ext/etc/selinux/system_ext_sepolicy.cil').decode()
    labeled_paths = re.findall(r'\(genfscon sysfs "([^"]+)" \([^\n]*\bsysfs_gta3xlwifi_touch_power\b', policy)
    assert set(labeled_paths) == set(labels), labeled_paths
    permission = re.search(r'\(allow system_server sysfs_gta3xlwifi_touch_power \(file \(([^)]*)\)\)\)', policy)
    assert permission and {'read', 'write', 'open', 'getattr'} <= set(permission.group(1).split())
    report['two_boolean_controls_labeled'] = True
    report['system_server_control_permissions'] = sorted(permission.group(1).split())
    report['factory_command_access_added'] = False
    with tempfile.TemporaryDirectory() as directory:
        apk = Path(directory)/'framework-res.apk'
        apk.write_bytes(archive.read('SYSTEM/framework/framework-res.apk'))
        resources = subprocess.check_output([str(args.top/'out/host/linux-x86/bin/aapt2'),
                                             'dump', 'resources', str(apk)], text=True)
        value = re.search(r'bool/config_supportDoubleTapWake\n\s+\(\) (true|false)\b', resources)
        assert value and value.group(1) == 'true', 'Packaged DT2W framework capability is disabled'
        report['framework_double_tap_supported'] = True
    props = dict(line.split('=', 1) for line in archive.read('SYSTEM/build.prop').decode().splitlines()
                 if '=' in line and not line.startswith('#'))
    report['build_incremental'] = props['ro.build.version.incremental']
    report['platform_security_patch'] = props['ro.build.version.security_patch']
report['passed'] = True
args.report.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
