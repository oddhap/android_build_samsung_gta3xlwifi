#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Archive the proven full product and validate actual vendor/factory APEX metadata.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$L/build.lock"; flock -n 9 || exit 75
[[ $(cat "$L/runtime-product-build-20261116-01.exit") == 0 ]] || exit 1
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
archive=$T/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
hash=$(python3 - "$A/runtime-product-checks-20261116-01/geometry-policy.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));assert r['artifact_checks_passed'] and r['ota_layout']['physical_non_ab'] and not r['flash_ready'];print(r['archive_sha256'])
PY
)
[[ $hash =~ ^[0-9a-f]{64}$ ]] || exit 1
cp --reflink=auto "$archive" "$O/lineage_gta3xlwifi-target_files.zip"
sha256sum "$O/lineage_gta3xlwifi-target_files.zip" >"$O/SHA256SUMS"
[[ $(cut -d' ' -f1 "$O/SHA256SUMS") == "$hash" ]] || exit 1
printf '%s\n' 'Full product target-files only. Android 17 installer/FBE/Keymaster/rollback validation remains. NOT AN INSTALLABLE OTA; DO NOT FLASH.' >"$O/NOT_READY_FOR_FLASHING.txt"
python3 "$P/tools/check-packaged-vendor-vintf.py" --top "$T" --archive "$O/lineage_gta3xlwifi-target_files.zip" --expected-archive-sha256 "$hash" --vendor "$A/vendor-composition-20261116-01/after/tree" --kernel-config "$A/kernel-uid-receipt-build-20261115-01/kernel.config" --output "$O/vintf"
