#!/usr/bin/env python3
"""Require a native system charger UI and its charger-only init service in the signed ROM."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('target_files', type=Path)
parser.add_argument('--report', type=Path, required=True)
parser.add_argument('--init-verifier', type=Path, required=True)
args = parser.parse_args()
with zipfile.ZipFile(args.target_files) as archive:
    rc = archive.read('SYSTEM/etc/init/init.gta3xlwifi.charger.rc')
    executable = archive.read('SYSTEM/bin/charger')
    lines = [line.strip() for line in rc.decode().splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    assert lines == ['service charger /system/bin/charger', 'class charger',
                     'user root', 'group root system graphics input wakelock',
                     'capabilities SYS_BOOT', 'file /dev/kmsg w'], lines
    assert executable[:5] == b'\x7fELF\x02'
    assert struct.unpack_from('<H', executable, 18)[0] == 183
    images = [archive.read('SYSTEM/etc/res/images/charger/'+name)
              for name in ('battery_scale.png', 'battery_fail.png')]
    assert all(image.startswith(b'\x89PNG\r\n\x1a\n') for image in images)
    animation = archive.read('PRODUCT/etc/res/values/charger/animation.txt').decode()
    assert any(line.startswith('percent_display:') for line in animation.splitlines())
    for name in ('battery_scale.png', 'battery_fail.png', 'percent_font.png'):
        assert archive.read('PRODUCT/etc/res/images/charger/'+name).startswith(b'\x89PNG\r\n\x1a\n')
    props = dict(line.split('=', 1) for line in archive.read('SYSTEM/build.prop').decode().splitlines()
                 if '=' in line and not line.startswith('#'))
    assert props.get('ro.charger.no_ui', 'false') not in ('true', '1')
args.report.parent.mkdir(parents=True, exist_ok=True)
import tempfile
with tempfile.TemporaryDirectory() as directory:
    init = Path(directory)/'init.gta3xlwifi.charger.rc'
    init.write_bytes(rc)
    subprocess.run([str(args.init_verifier), str(init)], check=True)
report = {'passed': True, 'build_incremental': props['ro.build.version.incremental'],
          'native_charger_bits': 64, 'charger_ui_not_disabled': True,
          'charger_class_only': True, 'starts_android_main_classes': False,
          'init_verifier_passed': True, 'battery_png_resources_present': True, 'lineage_animation_and_percentage_font_present': True,
          'charger_sha256': hashlib.sha256(executable).hexdigest(),
          'init_rc_sha256': hashlib.sha256(rc).hexdigest(), 'hardware_tested': False}
args.report.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
