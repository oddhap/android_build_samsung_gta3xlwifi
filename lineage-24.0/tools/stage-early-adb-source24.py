#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage early USB ADB for the development test ROM; retain secure key authentication."""
from pathlib import Path
import hashlib,json,shutil
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');O=A/'early-adb-source-composition-20261117-01';assert not O.exists();O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
f='device/samsung/gta3xlwifi/rootdir/init.gta3xlwifi.compat.rc';b=T/f;s=b.read_text();assert 'sys.usb.config' not in s
s+='''
# Development test ROM: enable the retained authenticated USB ADB transport before
# framework UI is available. No TCP listener or authentication bypass is added.
# The preserved vendor USB rc remains the sole configfs owner (value 2).
on post-fs-data
    setprop persist.sys.usb.config adb

on boot
    setprop sys.usb.config adb
'''
for kind in ['baseline','files']:
 d=O/kind/f;d.parent.mkdir(parents=True,exist_ok=True);d.write_text(b.read_text() if kind=='baseline' else s)
(O/'selection.json').write_text(json.dumps({'files':{f:{'before':sha(b),'after':sha(O/'files'/f)}},'scope':__doc__,'authentication_disabled':False,'tcp_listener_enabled':False,'SELinux_changed':False},indent=2)+'\n')
