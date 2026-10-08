#!/usr/bin/env python3
"""Install the validated OTA in existing TWRP; never format or reboot on failure."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--backup', type=Path, required=True)
args = parser.parse_args()
os.umask(0o077)
root = Path(__file__).resolve().parent.parent
adb = '/opt/homebrew/bin/adb'
release = root/'artifacts/release'
validation = json.loads((release/'offline-validation.json').read_text())
signatures = json.loads((release/'release-signature-check.json').read_text())
assert validation['passed'] and signatures['passed']
assert validation['rom_zip_sha256'] == signatures['rom_zip_sha256']
assert signatures['vendor_unmounted_guard_before_writes']
assert not (root/'.private/frozen-recovery.pid').exists(), 'Backup is still running'
backup = json.loads(args.backup.read_text())
for part, size in (('userdata', 58183385088), ('efs', 20971520)):
    item = backup['partitions'][part]
    assert item['gzip_crc_and_length_validated'] and item['raw_bytes'] == size
    assert Path(item['path']).is_file()

def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(8*1024*1024), b''):
            value.update(chunk)
    return value.hexdigest()

def shell(command):
    return subprocess.check_output([adb, 'shell', command], text=True).strip()

# Keep both the stock vendor and the known ARM32 OTA available for rollback.
baseline = root/'.private/device-baseline'
expected = {Path(line.split()[-1]).name: line.split()[0]
            for line in (baseline/'SHA256SUMS').read_text().splitlines()}
assert (baseline/'vendor.img').stat().st_size == 343932928
assert digest(baseline/'vendor.img') == expected['vendor.img']
old_rom = Path('/Users/oddi/Documents/Samsung/publication/assets/lineage-21.0-20261005-UNOFFICIAL-gta3xlwifi.zip')
assert digest(old_rom) == '94110cab46fa1edf908914dfbcc3c910ec5e5e16f306a810e13e673d3d5b597b'
assert shell('getprop ro.product.device') == 'gta3xlwifi'
assert shell('getprop ro.twrp.version') == '3.7.1_12'
assert shell('test -d /data/media/0/Download && echo readable') == 'readable'
assert shell('sha256sum /tmp/lineage-arm64.zip').split()[0] == validation['rom_zip_sha256']
for part in ('userdata', 'efs'):
    assert shell('blockdev --getro /dev/block/platform/13500000.dwmmc0/by-name/'+part) == '0'
for service in ('keystore2','recovery-keymaster','recovery-gatekeeper','recovery-mobicore','recovery-crypto-props'):
    shell('stop '+service)
if any(line.split()[1] == '/vendor' for line in shell('cat /proc/mounts').splitlines()):
    shell('umount /vendor')
assert not any(line.split()[1] == '/vendor' for line in shell('cat /proc/mounts').splitlines())
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
logs = root/'.private'/f'arm64-install-{stamp}'
logs.mkdir(mode=0o700)
print('Rollback inputs and backup validated; installing the signed ARM64 OTA.', flush=True)
previous_bytes = int(shell('wc -c /tmp/recovery.log').split()[0])
with (logs/'install.log').open('w') as output:
    result = subprocess.run([adb,'shell','twrp','install','/tmp/lineage-arm64.zip'],
                            stdout=output, stderr=subprocess.STDOUT)
subprocess.run([adb,'pull','/tmp/recovery.log',str(logs/'recovery.log')], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
data = (logs/'recovery.log').read_bytes()
assert len(data) >= previous_bytes, 'Recovery log restarted during installation'
text = data[previous_bytes:].decode(errors='replace')
codes = re.findall(r'Updater process ended with (?:RC=|ERROR: )(\d+)', text)
assert result.returncode == 0 and codes and codes[-1] == '0', f'Install did not pass; see {logs}'
assert 'Error installing zip file' not in text, f'Install failed; see {logs}'
report = {'installed_at_utc':stamp, 'rom_zip_sha256':validation['rom_zip_sha256'],
          'build_incremental':validation['build_incremental'], 'updater_exit_code':0,
          'boot_tested':False, 'data_formatted':False, 'passed':True}
(root/'artifacts/arm64-install-check.json').write_text(json.dumps(report,indent=2)+'\n')
print('OTA installer passed. Device remains in TWRP for post-write checks.', flush=True)
