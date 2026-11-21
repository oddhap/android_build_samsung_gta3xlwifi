#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 41: installed snapshot40 (product in system) + scoped ION read for
# priv_app_all (priv_app, priv_app_36) and gmscore_app (owner requested after the
# build-40 GApps test). Every step stops the chain on failure.
set -euo pipefail
R=/srv/android/ports/lineage-24.0-arm64
P=$R/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
S=$A/gmsion-policy-strict-20261121-01
V=$A/gmsion-policy-vendor-20261121-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime40-ota-checks-20261121-01.exit") == 0 ]]
[[ $(cat "$L/btaudio-shim-build-20261120-04.exit") == 0 ]]
python3 -c 'import json,sys;assert json.load(open(sys.argv[1]))["passed"]' "$A/btaudio-shim-build-20261120-04/abi-v30.json"
stage() {
    flock -n "$L/build.lock" bash -c '
        set -e
        source /srv/android/ports/lineage-24.0-arm64/env.sh
        python3 "$1" "$2"
    ' bash "$P/tools/stage-runtime41-source24.py" "$1"
}
[[ -f $A/runtime40-policy-baseline-20261121-01/freeze.json ]] || flock -n "$L/build.lock" python3 "$P/tools/freeze-runtime40-policy-baseline24.py" "$A/runtime40-policy-baseline-20261121-01"
stage policy
bash "$P/tools/build-runtime41-policy24.sh" gmsion-policy-build-20261121-01
[[ $(cat "$L/gmsion-policy-build-20261121-01.exit") == 0 ]]
bash "$P/tools/check-runtime41-policy24.sh" gmsion-policy-strict-20261121-01
[[ $(cat "$L/gmsion-policy-strict-20261121-01.exit") == 0 ]]
python3 - "$A" "$S" <<'PY'
from pathlib import Path
import json,sys
a,s=map(Path,sys.argv[1:])
keys=('source','target','class','permission')
rows=json.loads((a/'ion2-policy-strict-20261120-01/ion2-query-plan.json').read_text())
r=lambda d:f'u:r:{d}:s0'
o=lambda t:f'u:object_r:{t}:s0'
new=[]
app=r
for d in ('priv_app','priv_app_36','gmscore_app'):
    new+=[(app(d),o('ion_device'),'chr_file',p,'allow') for p in ('open','read','ioctl','map','getattr')]
    new+=[(app(d),o('ion_device'),'chr_file','write','deny'),(app(d),o('device'),'chr_file','read','deny'),
          (app(d),o('vendor_firmware_file'),'system','firmware_load','deny')]
# Unchanged neighbours: platform_app_36 and isolated apps get nothing new.
for d in ('platform_app_36','isolated_app'):
    new+=[(app(d),o('ion_device'),'chr_file','read','deny')]
rows=[x for x in rows if (x['source'],x['target'],x['class'],x['permission']) not in {(a_,b_,c_,p_) for a_,b_,c_,p_,_ in new}]
rows+=[{'source':s_,'target':t_,'class':c,'permission':p,'expected':e} for s_,t_,c,p,e in new]
seen={};[seen.setdefault(tuple(x[k] for k in keys),x) for x in rows]
(s/'gmsion-query-plan.json').write_text(json.dumps(list(seen.values()),indent=2)+'\n')
PY
flock -n "$L/build.lock" python3 "$P/tools/query-strict-policy-access.py" --top "$T" --policy "$S/strict/strict.policy" --queries "$S/gmsion-query-plan.json" --output "$A/gmsion-built-access-20261121-01"
flock -n "$L/build.lock" python3 "$P/tools/check-runtime41-labels24.py" "$A/gmsion-built-labels-20261121-01"
python3 "$P/tools/compose-runtime41-ion-vendor24.py" --top "$T" --strict-report "$S/strict/report.json" --vendor-metadata "$S/metadata/vendor" --output "$V" --supplicant-as-wifi
python3 "$P/tools/compose-btaudio-vendor24.py" --top "$T" --base-vendor "$V" --shim-build "$A/btaudio-shim-build-20261120-04" --staging "$R/btaudio-shim24-20261120-04" --output "$A/gmsion-vendor-20261121-01"
stage ota
python3 "$P/tools/select-runtime41-inputs24.py"
bash "$P/tools/build-runtime41-product24.sh" runtime41-product-build-20261121-01 "$A/runtime41-inputs-20261121-01/report.json"
bash "$P/tools/run-runtime41-package24.sh"
