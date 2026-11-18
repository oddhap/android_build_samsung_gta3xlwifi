#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Update the exact OTA vendor identity to the strictly audited Wi-Fi service configuration."""
from pathlib import Path
import hashlib,json
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');O=A/'wifi-ota-binding-composition-20261118-01';assert not O.exists();O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
v=A/'ion-ui-vendor-20261118-01/report.json';r=json.loads(v.read_text());assert r['passed'] and r['all_other_contents_and_security_metadata_identical'];assert sha(T/'device/samsung/gta3xlwifi/prebuilt/vendor.img')==r['vendor_sparse_sha256']
previous=r['vendor_sparse_sha256'];v=A/'wifi-supplicant-vendor-20261118-02/report.json';r=json.loads(v.read_text());assert r['passed'] and r['all_other_contents_and_security_metadata_identical'];assert sha(v.parent/'vendor.img')==r['vendor_sparse_sha256']
f='device/samsung/gta3xlwifi/releasetools.py';b=T/f;s=b.read_text();old=previous;assert s.count(old)==1;s=s.replace(old,r['vendor_sparse_sha256']);assert s.count(r['vendor_sparse_sha256'])==1
for kind in ['baseline','files']:
 d=O/kind/f;d.parent.mkdir(parents=True,exist_ok=True);d.write_text(b.read_text() if kind=='baseline' else s)
(O/'selection.json').write_text(json.dumps({'files':{f:{'before':sha(b),'after':sha(O/'files'/f)}},'scope':__doc__,'vendor_report_sha256':sha(v),'expected_vendor_sparse_sha256':r['vendor_sparse_sha256'],'guard_removed':False},indent=2)+'\n')
