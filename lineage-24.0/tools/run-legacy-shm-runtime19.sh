#!/usr/bin/env bash
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=legacy-shm-runtime19-preparation-20261117-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/legacy-shm-policy-strict-20261117-01.exit ]]; do
 if [[ -f $L/legacy-shm-policy-build-20261117-01.exit && $(cat "$L/legacy-shm-policy-build-20261117-01.exit") != 0 ]]; then exit 1; fi
 sleep 5
done
[[ $(cat "$L/legacy-shm-policy-strict-20261117-01.exit") == 0 ]]; sleep 2
python3 "$P/tools/check-legacy-shm-labels24.py" "$A/legacy-shm-built-labels-20261117-01"
python3 - "$A" <<'PY'
from pathlib import Path
import json,sys
A=Path(sys.argv[1]);q=json.loads((A/'ion-compat-probe-20261117-02/queries.json').read_text())+json.loads((A/'legacy-shm-probe-20261117-01/queries.json').read_text())
for s in ['system_server','zygote','audioserver','platform_app','priv_app','untrusted_app']:
 for perm in ['getattr','read','write','ioctl','map']:
  q.append(dict(source='u:r:'+s+':s0',target='u:object_r:ashmem_libcutils_device:s0',**{'class':'chr_file'},permission=perm,expected='allow'))
q.append(dict(source='u:r:bootanim:s0',target='u:object_r:ion_device:s0',**{'class':'chr_file'},permission='write',expected='deny'))
f=A/'legacy-shm-built-queries-20261117-01.json';assert not f.exists();f.write_text(json.dumps(q,indent=2)+'\n')
PY
python3 "$P/tools/query-strict-policy-access.py" --top "$T" --policy "$A/legacy-shm-policy-strict-20261117-01/strict/strict.policy" --queries "$A/legacy-shm-built-queries-20261117-01.json" --output "$A/legacy-shm-built-access-20261117-01"
python3 "$P/tools/compose-ion-vendor24.py" --top "$T" --strict-report "$A/legacy-shm-policy-strict-20261117-01/strict/report.json" --vendor-metadata "$A/legacy-shm-policy-strict-20261117-01/metadata/vendor" --output "$A/legacy-shm-vendor-composition-20261117-01"
python3 "$P/tools/select-legacy-shm-runtime-inputs24.py" "$A/runtime18-inputs-20261117-01"
flock -n "$L/build.lock" python3 "$P/tools/stage-vendor-ota-binding19.py"
python3 "$P/tools/test-vendor-ota-binding19.py"
python3 "$P/tools/compose-vendor-ota-binding19-source24.py" --top "$T" --ports /srv/android/ports/lineage-24.0-arm64 --composition "$A/vendor-ota-binding19-composition-20261117-01" --parent "$P/snapshots/port-20261117-18" --snapshot "$P/snapshots/port-20261117-19" --output "$A/vendor-ota-binding19-source-selection-20261117-01"
python3 "$P/tools/inherit-runtime19-inputs24.py" "$A/runtime19-inputs-20261117-01"
bash "$P/tools/build-runtime19-product24.sh" runtime19-product-build-20261117-01 "$A/runtime19-inputs-20261117-01/report.json"
bash "$P/tools/run-runtime19-package24.sh"
