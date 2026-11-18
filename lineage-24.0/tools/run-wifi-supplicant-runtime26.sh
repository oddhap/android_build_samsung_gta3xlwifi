#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
R=/srv/android/ports/lineage-24.0-arm64
P=$R/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
[[ $(cat "$L/runtime25-package-workflow-20261118-01.exit") == 0 ]]
python3 "$P/tools/check-wifi-supplicant-vendor24.py" "$A/ion-ui-vendor-20261118-01" "$A/wifi-supplicant-vendor-20261118-02" "$A/wifi-supplicant-vendor-20261118-02/snapshot25-delta.json"
flock -n "$L/build.lock" python3 "$P/tools/stage-wifi-ota-binding24.py"
python3 "$P/tools/test-wifi-ota-binding24.py"
python3 "$P/tools/compose-wifi-ota-binding24.py" --top "$T" --ports "$R" --composition "$A/wifi-ota-binding-composition-20261118-01" --parent "$P/snapshots/port-20261118-25" --snapshot "$P/snapshots/port-20261118-26" --output "$A/wifi-ota-source-selection-20261118-01"
python3 "$P/tools/select-wifi-runtime26.py"
bash "$P/tools/build-runtime26-product24.sh" runtime26-product-build-20261118-01 "$A/runtime26-inputs-20261118-01/report.json"
bash "$P/tools/run-runtime26-package24.sh"
