#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select the BPF-only local-network observation listener only for its backend.

The existing legacy backend enforces real local-network permissions but has no
BPF note-op stream. Current AOSP produces that stream only on kernel >=5.10.
Keep permission propagation and all modern listener behavior unchanged; expose
the unavailable optional observation feature honestly, without fabricated FDs.
"""
from pathlib import Path
import hashlib,json
T=Path('/srv/android/src/lineage-24.0-arm64');O=Path('/srv/android/artifacts/lineage-24.0-arm64/local-note-listener-source-composition-20261117-01');O.mkdir()
rel='packages/modules/Connectivity/service/src/com/android/server/ConnectivityService.java';s=(T/rel).read_text();old='''        if (mDeps.isAtLeastB()) {
            mLocalNetEventListener = mDeps.getLocalNetEventListener(''';assert s.count(old)==1
new='''        // This listener consumes only the BPF local-network note-op stream.
        // The legacy backend enforces local-network permissions in its kernel
        // hooks, but provides no such observation stream. AOSP's BPF producer
        // itself requires kernel >= 5.10. Preserve permission flags/enforcement
        // and avoid constructing an unavailable BPF transport on Linux 4.4.
        if (mDeps.isAtLeastB() && !mBpfNetMaps.usesGta3xlwifiNetworking()) {
            mLocalNetEventListener = mDeps.getLocalNetEventListener('''
for folder,text in [('baseline',s),('files',s.replace(old,new,1))]:
 f=O/folder/rel;f.parent.mkdir(parents=True);f.write_text(text)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(O/'selection.json').write_text(json.dumps(dict(scope=__doc__,files={rel:dict(before=sha(O/'baseline'/rel),after=sha(O/'files'/rel))},permission_flags_changed=False,enforcement_changed=False,BPF_readiness_synthesized=False,legacy_local_network_note_ops_available=False),indent=2)+'\n');print('Staged explicit backend applicability for the BPF observation listener')
