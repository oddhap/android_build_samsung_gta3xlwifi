#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 45: snapshot44 + TWRP vendor quiesce in releasetools (unattended Updater install),
# the second consecutive build for the Updater OTA end-to-end test. Starts only after
# build 44's complete package workflow passed. Every step stops the chain on failure.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
T=/srv/android/src/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime44-ota-checks-20261121-01.exit ]]; do sleep 30; done
[[ $(cat "$L/runtime44-ota-checks-20261121-01.exit") == 0 ]]
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261121-44" "$A/runtime45-orchestrator-source-before.json"
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime45-source24.py"
bash "$P/tools/build-runtime45-product24.sh" runtime45-product-build-20261121-01 "$A/runtime45-inputs-20261121-01/report.json"
bash "$P/tools/run-runtime45-package24.sh"
