#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the vendor delta against the image physically tested with snapshot25."""
import hashlib
import json
import sys
from pathlib import Path

previous, candidate, result = map(Path, sys.argv[1:])
path = '/etc/init/android.hardware.wifi.supplicant-service.rc'

def load(p):
    return json.loads(p.read_text())

old = load(previous / 'after/report.json')['entries']
new = load(candidate / 'after/report.json')['entries']
assert old.keys() == new.keys()
assert [name for name in old if old[name] != new[name]] == [path]
for key in old[path].keys() - {'size', 'sha256'}:
    assert new[path][key] == old[path][key]
before = (previous / 'after/tree' / path.lstrip('/')).read_bytes()
after = (candidate / 'after/tree' / path.lstrip('/')).read_bytes()
assert hashlib.sha256(before).hexdigest() == old[path]['sha256']
assert hashlib.sha256(after).hexdigest() == new[path]['sha256']
removed = b"""    #   we will start as root and wpa_supplicant will switch to user wifi
    #   after setting up the capabilities required for WEXT
    #   user wifi
    #   group wifi inet keystore
"""
added = b"""    # Android 17 init starts this retained HIDL service as Wi-Fi.
    user wifi
    group wifi inet keystore net_raw net_admin
    capabilities NET_RAW NET_ADMIN
"""
assert before.count(removed) == 1 and before.replace(removed, added) == after
pr = load(previous / 'report.json')
cr = load(candidate / 'report.json')
assert pr['passed'] and cr['passed']
assert pr['strict_report_sha256'] == cr['strict_report_sha256']
assert cr['changed_paths'][path] == new[path]['sha256']
with result.open('x') as f:
    json.dump({'passed': True, 'changed_path': path, 'previous_sha256': old[path]['sha256'],
               'service_sha256': new[path]['sha256'], 'vendor_sparse_sha256': cr['vendor_sparse_sha256'],
               'vendor_raw_sha256': cr['vendor_raw_sha256'], 'vendor_executables_unchanged': True,
               'compiled_policy_unchanged': True, 'hardware_validated': False}, f, indent=2)
    f.write('\n')
print('PASS exact vendor service delta, preserved labels and unchanged policy')
