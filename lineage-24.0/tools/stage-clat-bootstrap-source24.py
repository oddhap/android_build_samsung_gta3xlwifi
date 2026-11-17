#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage native selection of the existing userspace CLAT backend and optional flag containers.

No BPF readiness, map or capability is synthesized. Common daemon permission
checks still fail closed; modern BPF checks are unchanged for the BPF backend.
Only containers successfully initialized from genuine flag files get overrides.
"""
from pathlib import Path
import hashlib,json
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');O=A/'clat-bootstrap-source-composition-20261117-01';O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();files={}
def stage(rel,new):
 old=T/rel;before=O/'baseline'/rel;dest=O/'files'/rel
 for p in [before,dest]:p.parent.mkdir(parents=True,exist_ok=True)
 before.write_bytes(old.read_bytes());dest.write_text(new);files[rel]=dict(before=sha(old),after=sha(dest))
f='packages/modules/Connectivity/service/jni/com_android_server_connectivity_ClatCoordinator.cpp';s=(T/f).read_text();needle='#include <android-modules-utils/sdk_level.h>';assert s.count(needle)==1;s=s.replace(needle,needle+'\n#include <android-base/properties.h>')
needle='    // Move on to verifying that the bpf programs and maps are as expected.';assert s.count(needle)==1
s=s.replace(needle,'''    // This product uses the existing Java userspace CLAT path, including real
    // privileged socket tagging/accounting. Its JNI registration happens before
    // the Java owner is created. Select the same immutable backend here; do not
    // require or advertise BPF offload for this path. The shared daemon files
    // above must still have their exact ownership, mode and SELinux contexts.
    if (base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
        if (fatal) abort();
        return;
    }

'''+needle);stage(f,s)
f='packages/modules/ConfigInfrastructure/aconfigd/src/aconfigd.rs';s=(T/f).read_text();needle='    pub fn initialize_platform_storage(&mut self) -> Result<(), AconfigdError> {\n';assert s.count(needle)==1;s=s.replace(needle,needle+'        let mut initialized_containers = Vec::new();\n',1)
start=s.index(needle);end=s.index('    /// Initialize mainline storage files',start);part=s[start:end];needle='                &default_flag_info,\n            )?;';assert part.count(needle)==1;part=part.replace(needle,needle+'\n            initialized_containers.push(container);')
needle='        for container in ["system", "system_ext", "product", "vendor"] {\n            self.storage_manager.apply_all_staged_overrides(container, fsync_required)?;\n        }';assert part.count(needle)==1;part=part.replace(needle,'''        // Missing or empty optional containers were not initialized above.
        // Keep errors from all genuinely initialized containers observable.
        for container in initialized_containers {
            self.storage_manager.apply_all_staged_overrides(container, fsync_required)?;
        }''');s=s[:start]+part+s[end:];stage(f,s)
(O/'selection.json').write_text(json.dumps(dict(files=files,scope=__doc__,compiled_policy_rules_changed=False,flag_values_or_services_disabled=False,BPF_readiness_synthesized=False),indent=2)+'\n');print('Staged native CLAT backend selection and genuine initialized-container overrides')
