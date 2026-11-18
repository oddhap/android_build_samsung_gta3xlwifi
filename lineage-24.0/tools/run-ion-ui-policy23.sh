#!/usr/bin/env bash
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
flock -n /srv/android/logs/lineage-24.0-arm64/build.lock python3 "$P/tools/stage-ion-ui-source24.py"
python3 "$P/tools/compose-ion-ui-source24.py" --top "$T" --ports /srv/android/ports/lineage-24.0-arm64 --composition "$A/ion-ui-source-composition-20261117-01" --parent "$P/snapshots/port-20261117-22" --snapshot "$P/snapshots/port-20261117-23" --output "$A/ion-ui-source-selection-20261117-01"
bash "$P/tools/build-ion-ui-policy24.sh" ion-ui-policy-build-20261117-01
bash "$P/tools/check-ion-ui-policy24.sh" ion-ui-policy-strict-20261117-01
