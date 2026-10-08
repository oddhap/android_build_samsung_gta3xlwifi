#!/usr/bin/env python3
"""Restore verified stock vendor and the ARM32 OTA without formatting data."""
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

os.umask(0o077)
root = Path(__file__).resolve().parent.parent
adb = '/opt/homebrew/bin/adb'
baseline = root/'.private/device-baseline'
vendor = baseline/'vendor.img'
rom = Path('/Users/oddi/Documents/Samsung/publication/assets/lineage-21.0-20261005-UNOFFICIAL-gta3xlwifi.zip')
block = '/dev/block/platform/13500000.dwmmc0/by-name/vendor'

def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(8*1024*1024), b''):
            value.update(chunk)
    return value.hexdigest()

def shell(command):
    return subprocess.check_output([adb,'shell',command], text=True).strip()

manifest = {Path(line.split()[-1]).name: line.split()[0]
            for line in (baseline/'SHA256SUMS').read_text().splitlines()}
assert vendor.stat().st_size == 343932928 and digest(vendor) == manifest['vendor.img']
assert digest(rom) == '94110cab46fa1edf908914dfbcc3c910ec5e5e16f306a810e13e673d3d5b597b'
backup = json.loads((root/'.private/device-pre-arm64-20261007/data-backup.json').read_text())
for part, size in (('userdata',58183385088),('efs',20971520)):
    item = backup['partitions'][part]
    assert item['gzip_crc_and_length_validated'] and item['raw_bytes'] == size
    assert Path(item['path']).is_file()
assert not (root/'.private/frozen-recovery.pid').exists()
assert shell('getprop ro.product.device') == 'gta3xlwifi'
assert shell('getprop ro.twrp.version') == '3.7.1_12'
assert shell('blockdev --getsize64 '+block) == '343932928'
assert shell('test -d /data/media/0/Download && echo readable') == 'readable'
for service in ('keystore2','recovery-keymaster','recovery-gatekeeper','recovery-mobicore','recovery-crypto-props'):
    shell('stop '+service)
if any(line.split()[1] == '/vendor' for line in shell('cat /proc/mounts').splitlines()):
    shell('umount /vendor')
assert not any(line.split()[1].startswith('/vendor') for line in shell('cat /proc/mounts').splitlines())
# TWRP's RAM-backed /tmp cannot hold both complete OTA ZIPs at once.
# Authoritative copies are already verified on the Mac; retain recovery logs.
shell('rm -f /tmp/lineage-arm64.zip /tmp/lineage-baseline.zip /tmp/vendor-baseline.img')
subprocess.run([adb,'push',str(vendor),'/tmp/vendor-baseline.img'],check=True)
assert shell('sha256sum /tmp/vendor-baseline.img').split()[0] == manifest['vendor.img']
shell('dd if=/tmp/vendor-baseline.img of='+block+' bs=1048576 && sync')
assert shell('sha256sum '+block).split()[0] == manifest['vendor.img']
shell('rm /tmp/vendor-baseline.img')
print('Original vendor restored; full partition readback matches.',flush=True)
subprocess.run([adb,'push',str(rom),'/tmp/lineage-baseline.zip'],check=True)
assert shell('sha256sum /tmp/lineage-baseline.zip').split()[0] == digest(rom)
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
logs = root/'.private'/f'baseline-rollback-{stamp}'
logs.mkdir(mode=0o700)
previous_bytes = int(shell('wc -c /tmp/recovery.log').split()[0])
with (logs/'install.log').open('w') as output:
    result = subprocess.run([adb,'shell','twrp','install','/tmp/lineage-baseline.zip'],
                            stdout=output,stderr=subprocess.STDOUT)
subprocess.run([adb,'pull','/tmp/recovery.log',str(logs/'recovery.log')],check=True,
               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
data = (logs/'recovery.log').read_bytes()
assert len(data) >= previous_bytes
text = data[previous_bytes:].decode(errors='replace')
codes = re.findall(r'Updater process ended with (?:RC=|ERROR: )(\d+)',text)
assert result.returncode == 0 and codes and codes[-1] == '0', f'Rollback failed; see {logs}'
assert 'Error installing zip file' not in text
report = {'checked_at_utc':stamp,'stock_vendor_full_readback_matches':True,
          'baseline_ota_sha256':digest(rom),'updater_exit_code':0,
          'data_formatted':False,'boot_tested':False,'passed':True}
(root/'artifacts/baseline-rollback-check.json').write_text(json.dumps(report,indent=2)+'\n')
print('Baseline rollback installer passed; device remains in TWRP.',flush=True)
