#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$L/build.lock"; flock -n 9 || exit 75
[[ $(cat "$L/runtime05-product-build-20261116-01.exit") == 0 ]] || exit 1
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
archive=$T/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
python3 "$P/tools/check-runtime-target-files24.py" --top "$T" --archive "$archive" --snapshot "$P/snapshots/port-20261116-05" --source-audit "$A/runtime05-product-build-20261116-01/source-after.json" --build-exit "$L/runtime05-product-build-20261116-01.exit" --input-selection "$A/runtime05-inputs-20261116-01/report.json" --strict-report "$A/policy-composition-strict-20261116-01/strict/report.json" --vendor-report "$A/vendor-composition-20261116-01/report.json" --report "$O/geometry-policy.json"
python3 "$P/tools/test-installer-hooks24.py" --top "$T" --archive "$archive" --source "$T/device/samsung/gta3xlwifi/releasetools.py" --output "$O/hooks"
python3 "$P/tools/check-runtime-ext4-features24.py" --top "$T" --archive "$archive" --geometry-report "$O/geometry-policy.json" --kernel /srv/android/ports/lineage-24.0-arm64/kernel-uid-receipt-20261115-01/src --output "$O/ext4"

python3 "$P/tools/check-firststage-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/firststage.json"
