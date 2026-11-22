#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 48: snapshot46 + HWUI immutable-bitmap parcel fallback for kernels without
# memfd F_SEAL_FUTURE_WRITE (F-Droid "Could not copy bitmap to parcel blob").
# Stage, rebind unchanged inputs, full build, package checks, test OTA, then
# owner-approved release signing (release-20261122-02). Every step stops the chain.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime47-ota-checks-20261122-01.exit") == 0 ]]
[[ $(cat "$L/release-20261122-01-orchestrator.exit") == 0 ]]
test -f "$A/runtime47-ota-build-20261122-01/target-files.zip"
flock -n "$L/build.lock" bash -c 'set -e; source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime48-source24.py"
python3 "$P/tools/select-runtime48-inputs24.py"
bash "$P/tools/build-runtime48-product24.sh" runtime48-product-build-20261122-01 "$A/runtime48-inputs-20261122-01/report.json"
bash "$P/tools/run-runtime48-package24.sh"
[[ $(cat "$L/runtime48-package-workflow-20261122-01.exit") == 0 ]]
[[ $(cat "$L/runtime48-ota-checks-20261122-01.exit") == 0 ]]
bash "$P/tools/run-release-ota24.sh" release-20261122-02 runtime48-ota-build-20261122-01
[[ $(cat "$L/release-20261122-02-orchestrator.exit") == 0 ]]
