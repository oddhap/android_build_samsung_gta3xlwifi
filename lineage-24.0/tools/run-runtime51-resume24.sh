#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 51 resume after attempt a: product build and power host tests passed; product
# checks stopped in check-runtime28-touch because the runtime43 touch proof binds the
# old power/Power.cpp and power/Android.bp hashes. Attempt-a check, package-workflow and
# orchestrator logs/artifacts are kept as *-failed-a. Rebind the touch proof
# (rebind-runtime51-touch24.py), then re-run the package workflow and release signing
# on the unchanged build.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime51-product-build-20261123-01.exit") == 0 ]]
[[ $(cat "$L/runtime51-product-checks-20261123-01-failed-a.exit") == 1 ]]
[[ ! -e $L/runtime51-product-checks-20261123-01.exit && ! -e $L/runtime51-package-workflow-20261123-01.exit ]]
python3 "$P/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$P/snapshots/port-20261123-51" "$A/runtime51-resume-source-before.json"
flock -n "$L/build.lock" python3 "$P/tools/rebind-runtime51-touch24.py"
bash "$P/tools/run-runtime51-package24.sh"
[[ $(cat "$L/runtime51-package-workflow-20261123-01.exit") == 0 ]]
[[ $(cat "$L/runtime51-ota-checks-20261123-01.exit") == 0 ]]
bash "$P/tools/run-release-ota24.sh" release-20261123-01 runtime51-ota-build-20261123-01
[[ $(cat "$L/release-20261123-01-orchestrator.exit") == 0 ]]
