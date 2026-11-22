#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 47: snapshot46 rebuilt unchanged (new build date): the second consecutive build,
# published for the Updater OTA end-to-end test. Starts only after build 46's complete
# package workflow passed. Every step stops the chain on failure.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
T=/srv/android/src/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime46-package-workflow-20261122-01.exit ]]; do sleep 30; done
[[ $(cat "$L/runtime46-package-workflow-20261122-01.exit") == 0 ]]
[[ $(cat "$L/runtime46-ota-checks-20261122-01.exit") == 0 ]]
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261122-46" "$A/runtime47-orchestrator-source-before.json"
bash "$P/tools/build-runtime47-product24.sh" runtime47-product-build-20261122-01 "$A/runtime46-inputs-20261122-01/report.json"
bash "$P/tools/run-runtime47-package24.sh"
