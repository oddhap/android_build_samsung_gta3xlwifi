#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 36: installed snapshot35 + legacy-backend network-access wait (AMS default).
# Policy, vendor, kernel unchanged from build 35.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime35-ota-checks-20261120-01.exit") == 0 ]]
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime36-source24.py"
bash "$P/tools/build-runtime36-product24.sh" runtime36-product-build-20261120-01 "$A/runtime36-inputs-20261120-01/report.json"
bash "$P/tools/run-runtime36-package24.sh"
