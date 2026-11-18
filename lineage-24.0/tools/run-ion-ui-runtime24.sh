#!/usr/bin/env bash
set -euo pipefail
R=/srv/android/ports/lineage-24.0-arm64
P=$R/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
[[ $(cat "$L/ion-ui-policy-strict-20261117-01.exit") == 0 ]]
python3 - "$A" <<'PY'
from pathlib import Path
import json,sys
a=Path(sys.argv[1])
paths=['legacy-shm-built-queries-20261117-01.json','ion-ui-clients-probe-20261117-01/queries.json']
q=[item for p in paths for item in json.loads((a/p).read_text())]
(a/'ion-ui-built-queries-20261118-01.json').write_text(json.dumps(q,indent=2)+'\n')
PY
python3 "$P/tools/query-strict-policy-access.py" --top "$T" --policy "$A/ion-ui-policy-strict-20261117-01/strict/strict.policy" --queries "$A/ion-ui-built-queries-20261118-01.json" --output "$A/ion-ui-built-access-20261118-01"
flock -n "$L/build.lock" python3 "$P/tools/stage-ion-ui-ota-binding24.py"
python3 "$P/tools/test-ion-ui-ota-binding24.py"
python3 "$P/tools/compose-ion-ui-ota-binding24.py" --top "$T" --ports "$R" --composition "$A/ion-ui-ota-binding-composition-20261118-01" --parent "$P/snapshots/port-20261117-23" --snapshot "$P/snapshots/port-20261118-24" --output "$A/ion-ui-ota-source-selection-20261118-01"
python3 "$P/tools/select-ion-ui-runtime24.py"
bash "$P/tools/build-runtime24-product24.sh" runtime24-product-build-20261118-01 "$A/runtime24-inputs-20261118-01/report.json"
bash "$P/tools/run-runtime24-package24.sh"
