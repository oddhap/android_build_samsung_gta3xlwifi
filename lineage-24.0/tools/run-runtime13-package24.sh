#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime13-package-workflow-20261117-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime13-product-build-20261117-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime13-product-build-20261117-01.exit") == 0 ]]
bash "$P/tools/check-runtime13-product24.sh" runtime13-product-checks-20261117-01
bash "$P/tools/check-runtime13-vintf24.sh" runtime13-vintf-20261117-01
bash "$P/tools/build-runtime13-test-ota24.sh" runtime13-ota-build-20261117-01
bash "$P/tools/check-runtime13-ota24.sh" runtime13-ota-checks-20261117-01
