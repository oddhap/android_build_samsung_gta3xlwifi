#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 35: installed snapshot34 + enabled Bluetooth profiles (product props).
# Policy, vendor, kernel unchanged from build 34.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime34-ota-checks-20261120-01.exit") == 0 ]]
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime35-source24.py"
bash "$P/tools/build-runtime35-product24.sh" runtime35-product-build-20261120-01 "$A/runtime35-inputs-20261120-01/report.json"
bash "$P/tools/run-runtime35-package24.sh"
