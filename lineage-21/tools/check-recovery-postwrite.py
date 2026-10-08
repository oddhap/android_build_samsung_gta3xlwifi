#!/usr/bin/env python3
"""Read back the installed boot and hybrid vendor before the first reboot."""
import hashlib
import json
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parent.parent
adb = '/opt/homebrew/bin/adb'
blocks = '/dev/block/platform/13500000.dwmmc0/by-name/'

def shell(command):
    return subprocess.check_output([adb, 'shell', command], text=True).strip()

def read_partition(name, size):
    blocks_to_read = (size + 4095) // 4096
    data = subprocess.check_output([adb, 'exec-out',
        f'dd if={blocks}{name} bs=4096 count={blocks_to_read} 2>/dev/null'])
    assert len(data) == blocks_to_read * 4096, name
    return data[:size]

assert shell('getprop ro.twrp.version') == '3.7.1_12'
assert shell('getprop ro.product.device') == 'gta3xlwifi'
installed = json.loads((root/'artifacts/arm64-install-check.json').read_text())
assert installed['passed']
ota = root/'artifacts/release/lineage-21.0-20261007-UNOFFICIAL-gta3xlwifi-arm64-privatekeys.zip'
assert hashlib.sha256(ota.read_bytes()).hexdigest() == installed['rom_zip_sha256']
with zipfile.ZipFile(ota) as archive:
    boot = archive.read('boot.img')
assert read_partition('boot', len(boot)) == boot
baseline = root/'.private/device-baseline'
for name, size in (('dtbo', 8388608), ('vbmeta', 524288)):
    assert read_partition(name, size) == (baseline/(name+'.img')).read_bytes(), name
recovery = bytearray(read_partition('recovery', 47185920))
old_recovery = bytearray((baseline/'recovery.img').read_bytes())
assert recovery[44:48] == boot[44:48], 'Recovery OS version must match boot'
recovery[44:48] = old_recovery[44:48]
assert recovery == old_recovery, 'Recovery changed outside the four OS version bytes'
assert not any(line.split()[1].startswith('/vendor') for line in shell('cat /proc/mounts').splitlines())
shell(f'mount -t ext4 -o ro,noload {blocks}vendor /vendor')
checked = 0
try:
    vendor = json.loads((root/'artifacts/vendor-image-report.json').read_text())
    files = dict(vendor['added_files'])
    files.update({name: item['after'] for name, item in vendor['changed_stock_files'].items()})
    for name, expected in files.items():
        path = '/vendor/'+name
        if 'link' in expected:
            assert shell('readlink '+path) == expected['link'], name
        else:
            assert shell('sha256sum '+path).split()[0] == expected['sha256'], name
            actual = shell("stat -c '%a %u %g' "+path).split()
            assert (int(actual[0],8), int(actual[1]), int(actual[2])) == (
                expected['mode'], expected['uid'], expected['gid']), name
        assert expected['label'] in shell('ls -Zd '+path), name
        checked += 1
finally:
    shell('umount /vendor')
report = {'checked_at_utc': datetime.now(timezone.utc).isoformat(),
          'rom_zip_sha256': installed['rom_zip_sha256'], 'boot_readback_matches': True,
          'recovery_payload_preserved': True, 'dtbo_preserved': True,
          'vbmeta_preserved': True, 'vendor_added_and_changed_entries_checked': checked,
          'vendor_unmounted_after_check': True, 'boot_tested': False, 'passed': True}
(root/'artifacts/arm64-postwrite-check.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
