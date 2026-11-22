#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 49: snapshot48 + Updater "Recent changes" link to the device's GitHub
# releases (download.lineageos.org has no page for this unofficial device).
# Stage, rebind unchanged inputs, full build, package checks, test OTA, then
# owner-approved release signing (release-20261122-03). Every step stops the chain.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime48-ota-checks-20261122-01.exit") == 0 ]]
[[ $(cat "$L/release-20261122-02-orchestrator.exit") == 0 ]]
test -f "$A/runtime48-ota-build-20261122-01/target-files.zip"
flock -n "$L/build.lock" bash -c 'set -e; source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime49-source24.py"
python3 "$P/tools/select-runtime49-inputs24.py"
bash "$P/tools/build-runtime49-product24.sh" runtime49-product-build-20261122-01 "$A/runtime49-inputs-20261122-01/report.json"
bash "$P/tools/run-runtime49-package24.sh"
[[ $(cat "$L/runtime49-package-workflow-20261122-01.exit") == 0 ]]
[[ $(cat "$L/runtime49-ota-checks-20261122-01.exit") == 0 ]]
bash "$P/tools/run-release-ota24.sh" release-20261122-03 runtime49-ota-build-20261122-01
[[ $(cat "$L/release-20261122-03-orchestrator.exit") == 0 ]]
