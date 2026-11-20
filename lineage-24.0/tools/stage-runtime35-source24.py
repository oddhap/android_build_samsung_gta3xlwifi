#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot35: enable the Bluetooth profiles the stack may start.

Since Android 13 each profile is gated by bluetooth.profile.* (bluetooth_config_prop,
settable from product build.prop by init). Neither LineageOS 21 nor builds 29-34
set any, so only GATT/Hearing Aid started and A2DP was never attempted. Enable
A2DP source + AVRCP target (the HIDL 2.0 software datapath of the shim), battery,
HID host, OPP and PAN. LE Audio stays explicitly off (no HIDL 2.0 support); HFP
stays off (no SCO path in the shim). Policy, vendor and kernel are unchanged.
"""
import hashlib, json, subprocess
from pathlib import Path

src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261120-34', port/'snapshots/port-20261120-35'
work = art/'runtime35-bt-profiles-selection-20261120-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
f = src/'device/samsung/gta3xlwifi/device.mk'
original = f.read_text()
anchor = '''    ro.product.product.cpu.abilist32=armeabi-v7a,armeabi
'''
assert original.count(anchor) == 1 and 'bluetooth.profile' not in original
block = '''
# Android 13+ starts only the Bluetooth profiles enabled here. A2DP source and
# AVRCP target use the vendor HIDL 2.0 software datapath (btaudio shim). LE Audio
# has no HIDL 2.0 support and HFP has no SCO path in the shim, so both stay off.
PRODUCT_PRODUCT_PROPERTIES += \\
    bluetooth.profile.a2dp.source.enabled=true \\
    bluetooth.profile.avrcp.target.enabled=true \\
    bluetooth.profile.bas.client.enabled=true \\
    bluetooth.profile.gatt.enabled=true \\
    bluetooth.profile.hid.host.enabled=true \\
    bluetooth.profile.opp.enabled=true \\
    bluetooth.profile.pan.nap.enabled=true \\
    bluetooth.profile.pan.panu.enabled=true \\
    bluetooth.profile.bap.broadcast.assist.enabled=false \\
    bluetooth.profile.bap.broadcast.source.enabled=false \\
    bluetooth.profile.bap.unicast.client.enabled=false \\
    bluetooth.profile.bass.client.enabled=false \\
    bluetooth.profile.ccp.server.enabled=false \\
    bluetooth.profile.csip.set_coordinator.enabled=false \\
    bluetooth.profile.hap.client.enabled=false \\
    bluetooth.profile.hfp.ag.enabled=false \\
    bluetooth.profile.mcp.server.enabled=false \\
    bluetooth.profile.vcp.controller.enabled=false
'''
updated = original.replace(anchor, anchor+block)
(work/'device.mk.original').write_text(original)
(work/'edits.json').write_text(json.dumps({str(f): {'before_sha256': hashlib.sha256(original.encode()).hexdigest(),
    'after_sha256': hashlib.sha256(updated.encode()).hexdigest()}}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    f.write_text(updated)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    f.write_text(original)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime34-inputs-20261120-01/report.json'
r = json.loads(p.read_text())
assert r['passed']
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p), runtime_prebuilts_changed=False)
out = art/'runtime35-inputs-20261120-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot35 Bluetooth profiles:', after)
