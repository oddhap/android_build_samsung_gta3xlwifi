#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Snapshot32: installed snapshot31 + cameraserver scoped ION read + kernel
# audio-DSP firmware_load. Every step stops the chain on failure.
set -euo pipefail
R=/srv/android/ports/lineage-24.0-arm64
P=$R/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
S=$A/camera-policy-strict-20261120-01
V=$A/camera-policy-vendor-20261120-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime31-ota-checks-20261120-01.exit") == 0 ]]
stage() {
    flock -n "$L/build.lock" bash -c '
        set -e
        source /srv/android/ports/lineage-24.0-arm64/env.sh
        python3 "$1" "$2"
    ' bash "$P/tools/stage-runtime32-source24.py" "$1"
}
# Freeze the actual snapshot31 strict inputs before the policy build rewrites out/.
[[ -f $A/runtime31-policy-baseline-20261120-01/freeze.json ]] || flock -n "$L/build.lock" python3 "$P/tools/freeze-runtime31-policy-baseline24.py" "$A/runtime31-policy-baseline-20261120-01"
stage policy
bash "$P/tools/build-runtime32-policy24.sh" camera-policy-build-20261120-01
[[ $(cat "$L/camera-policy-build-20261120-01.exit") == 0 ]]
bash "$P/tools/check-runtime32-policy24.sh" camera-policy-strict-20261120-01
[[ $(cat "$L/camera-policy-strict-20261120-01.exit") == 0 ]]
python3 - "$A" "$S" <<'PY'
from pathlib import Path
import json,sys
a,s=map(Path,sys.argv[1:])
keys=('source','target','class','permission')
rows=json.loads((a/'firmware-policy-strict-20261120-03/firmware-query-plan.json').read_text())
r=lambda d:f'u:r:{d}:s0'
o=lambda t:f'u:object_r:{t}:s0'
new=[(r('cameraserver'),o('ion_device'),'chr_file',p,'allow') for p in ('open','read','ioctl','map','getattr')]
new+=[(r('cameraserver'),o('ion_device'),'chr_file','write','deny'),
      (r('cameraserver'),o('device'),'chr_file','read','deny'),
      (r('cameraserver'),o('vendor_firmware_file'),'system','firmware_load','deny'),
      (r('kernel'),o('vendor_firmware_file'),'system','firmware_load','allow'),
      (r('kernel'),o('system_file'),'system','firmware_load','deny'),
      (r('kernel'),o('app_data_file'),'system','firmware_load','deny'),
      (r('audioserver'),o('vendor_firmware_file'),'system','firmware_load','deny'),
      (r('hal_audio_default'),o('vendor_firmware_file'),'system','firmware_load','deny')]
rows=[x for x in rows if (x['source'],x['target'],x['class'],x['permission'])!=(r('kernel'),o('vendor_firmware_file'),'system','firmware_load')]
rows+=[{'source':s_,'target':t_,'class':c,'permission':p,'expected':e} for s_,t_,c,p,e in new]
seen={};[seen.setdefault(tuple(x[k] for k in keys),x) for x in rows]
(s/'camera-query-plan.json').write_text(json.dumps(list(seen.values()),indent=2)+'\n')
PY
flock -n "$L/build.lock" python3 "$P/tools/query-strict-policy-access.py" --top "$T" --policy "$S/strict/strict.policy" --queries "$S/camera-query-plan.json" --output "$A/camera-built-access-20261120-01"
flock -n "$L/build.lock" python3 "$P/tools/check-runtime32-labels24.py" "$A/camera-built-labels-20261120-01"
python3 "$P/tools/compose-ion-vendor24.py" --top "$T" --strict-report "$S/strict/report.json" --vendor-metadata "$S/metadata/vendor" --output "$V" --supplicant-as-wifi
stage ota
python3 "$P/tools/select-runtime32-inputs24.py"
bash "$P/tools/build-runtime32-product24.sh" runtime32-product-build-20261120-01 "$A/runtime32-inputs-20261120-01/report.json"
bash "$P/tools/run-runtime32-package24.sh"
