#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 38: installed snapshot37 + fixed boot image header patch level
# (BOOT_SECURITY_PATCH 2026-11-01 = installed TWRP header 0x220001ab), so new
# ASB months only raise the system level. Policy, vendor, kernel unchanged.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime37-ota-checks-20261120-01.exit") == 0 ]]
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime38-source24.py"
bash "$P/tools/build-runtime38-product24.sh" runtime38-product-build-20261121-01 "$A/runtime38-inputs-20261121-01/report.json"
bash "$P/tools/run-runtime38-package24.sh"
