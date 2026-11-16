#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime07-package-workflow-20261116-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime07-product-build-20261116-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime07-product-build-20261116-01.exit") == 0 ]]
bash "$P/tools/check-runtime07-product24.sh" runtime07-product-checks-20261116-01
bash "$P/tools/check-runtime07-vintf24.sh" runtime07-vintf-20261116-01
bash "$P/tools/build-runtime07-test-ota24.sh" runtime07-ota-build-20261116-01
bash "$P/tools/check-runtime07-ota24.sh" runtime07-ota-checks-20261116-01
