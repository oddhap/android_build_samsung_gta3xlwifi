#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 39: installed snapshot38 + recognition of the owner-approved TWRP
# (choice a, recovery 96b3de24...) in the read-only OTA recovery preflight.
# Policy, vendor, kernel and boot image unchanged.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime38-ota-checks-20261121-01.exit") == 0 ]]
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime39-source24.py"
bash "$P/tools/build-runtime39-product24.sh" runtime39-product-build-20261121-01 "$A/runtime39-inputs-20261121-01/report.json"
bash "$P/tools/run-runtime39-package24.sh"
