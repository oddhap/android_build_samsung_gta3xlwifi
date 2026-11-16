#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime05-package-workflow-20261116-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime05-product-build-20261116-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime05-product-build-20261116-01.exit") == 0 ]]
bash "$P/tools/check-runtime05-product24.sh" runtime05-product-checks-20261116-01
bash "$P/tools/check-runtime05-vintf24.sh" runtime05-vintf-20261116-01
bash "$P/tools/build-runtime05-test-ota24.sh" runtime05-ota-build-20261116-01
bash "$P/tools/check-runtime05-ota24.sh" runtime05-ota-checks-20261116-01
