#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime28-package-workflow-20261118-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime28-product-build-20261118-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime28-product-build-20261118-01.exit") == 0 ]]
bash "$P/tools/check-runtime28-product24.sh" runtime28-product-checks-20261118-01
bash "$P/tools/check-runtime28-vintf24.sh" runtime28-vintf-20261118-01
bash "$P/tools/build-runtime28-test-ota24.sh" runtime28-ota-build-20261118-01
bash "$P/tools/check-runtime28-ota24.sh" runtime28-ota-checks-20261118-01
