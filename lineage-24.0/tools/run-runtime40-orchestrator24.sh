#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 40: installed snapshot39 + /product folded into /system so the official
# MindTheGapps 17 ZIP fits (physical product partition left untouched, unused).
# Policy, vendor, kernel, boot image and recovery unchanged.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime39-ota-checks-20261121-01.exit") == 0 ]]
test -f "$A/gapps-mtg17-20261022/MindTheGapps-17.0.0-arm64-20261022_132445.zip"
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime40-source24.py"
flock -n "$L/build.lock" python3 "$P/tools/rebind-runtime40-boardconfig24.py" runtime40-boardconfig-rebind-20261121-01
flock -n "$L/build.lock" python3 "$P/tools/rebind-runtime40-devicemk24.py" runtime40-devicemk-rebind-20261121-01
bash "$P/tools/build-runtime40-product24.sh" runtime40-product-build-20261121-01 "$A/runtime40-inputs-20261121-01/report.json"
bash "$P/tools/run-runtime40-package24.sh"
