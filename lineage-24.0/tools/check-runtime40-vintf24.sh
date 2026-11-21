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
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
hash=$(python3 - "$A/runtime40-product-checks-20261121-01/geometry-policy.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));assert r['artifact_checks_passed'];print(r['archive_sha256'])
PY
)
python3 "$P/tools/check-runtime40-packaged-vendor-vintf.py" --top "$T" --archive "$T/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip" --expected-archive-sha256 "$hash" --vendor "$A/btaudio-vendor-20261120-01/after/tree" --kernel-config "$A/kernel-netpolicy-flush-build-20261120-01/kernel.config" --output "$O/vintf"
