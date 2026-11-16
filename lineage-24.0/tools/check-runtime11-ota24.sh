#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verify the complete replacement OTA. No device operation.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$L/build.lock"; flock -n 9 || exit 75
[[ $(cat "$L/runtime11-ota-build-20261116-01.exit") == 0 ]] || exit 1
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
ota=$A/runtime11-ota-build-20261116-01/lineage-24.0-20261116-UNOFFICIAL-gta3xlwifi-test.zip
target=$A/runtime11-ota-build-20261116-01/target-files.zip
geometry=$A/runtime11-product-checks-20261116-01/geometry-policy.json
python3 "$P/tools/check-test-ota-container24.py" --ota "$ota" --target-files "$target" --geometry "$geometry" --certificate "$T/build/make/target/product/security/testkey.x509.pem" --output "$A/runtime11-ota-container-20261116-01"
python3 "$P/tools/check-ota-block-streams24.py" --top "$T" --ota "$ota" --target-files "$target" --container "$A/runtime11-ota-container-20261116-01/report.json" --geometry "$geometry" --vendor-report "$A/vendor-composition-20261116-01/report.json" --output "$A/runtime11-ota-blocks-20261116-01"
python3 "$P/tools/summarize-runtime11-candidate24.py" --output "$A/runtime11-ota-build-20261116-01/readiness-report.json"
