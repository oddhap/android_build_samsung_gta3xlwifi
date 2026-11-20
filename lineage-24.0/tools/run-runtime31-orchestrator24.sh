#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Snapshot31: synced lineage-24.0 + NetworkStack legacy-backend fallback +
# scoped firmware_load. Every step stops the chain on failure.
set -euo pipefail
R=/srv/android/ports/lineage-24.0-arm64
P=$R/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
S=$A/firmware-policy-strict-20261120-03
V=$A/firmware-policy-vendor-20261120-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime31-policy-revert-20261120-02.exit") == 0 ]]
stage() {
    flock -n "$L/build.lock" bash -c '
        set -e
        source /srv/android/ports/lineage-24.0-arm64/env.sh
        python3 "$1" "$2"
    ' bash "$P/tools/stage-runtime31-source24.py" "$1"
}
stage policy
bash "$P/tools/build-runtime31-policy24.sh" firmware-policy-build-20261120-03
[[ $(cat "$L/firmware-policy-build-20261120-03.exit") == 0 ]]
[[ -f $A/runtime29-policy-baseline-20261120-01/freeze.json ]] || flock -n "$L/build.lock" python3 "$P/tools/freeze-runtime29-policy-baseline24.py" "$A/runtime29-policy-baseline-20261120-01"
bash "$P/tools/check-runtime31-policy24.sh" firmware-policy-strict-20261120-03
[[ $(cat "$L/firmware-policy-strict-20261120-03.exit") == 0 ]]
python3 - "$A" "$S" <<'PY'
from pathlib import Path
import json,sys
a,s=map(Path,sys.argv[1:])
keys=('source','target','class','permission')
rows=json.loads((a/'ordinary-app-ion-strict-20261118-01/ion-query-plan.json').read_text())
r=lambda d:f'u:r:{d}:s0'
o=lambda t:f'u:object_r:{t}:s0'
fw=[(r('hal_camera_default'),o('vendor_firmware_file'),'allow'),
    (r('mediacodec'),o('vendor_firmware_file'),'allow'),
    (r('ueventd'),r('ueventd'),'allow'),
    (r('kernel'),r('kernel'),'allow'),
    (r('untrusted_app'),o('vendor_firmware_file'),'deny'),
    (r('shell'),o('vendor_firmware_file'),'deny'),
    (r('system_server'),o('vendor_firmware_file'),'deny'),
    (r('init'),o('vendor_firmware_file'),'deny'),
    (r('ueventd'),o('vendor_firmware_file'),'deny'),
    (r('hal_camera_default'),r('hal_camera_default'),'deny'),
    (r('hal_camera_default'),o('vendor_npu_firmware_file'),'observe'),
    (r('hal_camera_default'),o('system_file'),'deny'),
    (r('mediacodec'),o('vendor_file'),'observe'),
    (r('hal_graphics_composer_default'),o('vendor_firmware_file'),'deny'),
    (r('mediaswcodec'),o('vendor_firmware_file'),'deny'),
    (r('mediaserver'),o('vendor_firmware_file'),'deny')]
rows+= [{'source':s_,'target':t_,'class':'system','permission':'firmware_load','expected':e} for s_,t_,e in fw]
seen={};[seen.setdefault(tuple(x[k] for k in keys),x) for x in rows]
(s/'firmware-query-plan.json').write_text(json.dumps(list(seen.values()),indent=2)+'\n')
PY
flock -n "$L/build.lock" python3 "$P/tools/query-strict-policy-access.py" --top "$T" --policy "$S/strict/strict.policy" --queries "$S/firmware-query-plan.json" --output "$A/firmware-built-access-20261120-02"
flock -n "$L/build.lock" python3 "$P/tools/check-runtime31-labels24.py" "$A/firmware-built-labels-20261120-02"
python3 "$P/tools/compose-ion-vendor24.py" --top "$T" --strict-report "$S/strict/report.json" --vendor-metadata "$S/metadata/vendor" --output "$V" --supplicant-as-wifi
stage ota
python3 "$P/tools/select-runtime31-inputs24.py"
bash "$P/tools/build-runtime31-product24.sh" runtime31-product-build-20261120-01 "$A/runtime31-inputs-20261120-01/report.json"
bash "$P/tools/run-runtime31-package24.sh"
