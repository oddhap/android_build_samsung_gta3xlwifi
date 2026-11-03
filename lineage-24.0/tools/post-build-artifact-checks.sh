#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Serialized offline checks/archiving after a successful diagnostic full build.
# No OTA generation, release signing or device access.
set -euo pipefail
full=${1:?FULL_BUILD_LABEL}
snapshot=${2:?SNAPSHOT_NAME}
label=${3:?FRESH_CHECK_LABEL}
for value in "$full" "$snapshot" "$label"; do
    [[ $value =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
done
top=/srv/android/src/lineage-24.0-arm64
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
art=/srv/android/artifacts/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
exec 8>"$logs/$label.lock"
flock -n 8 || exit 1
[[ ! -e $logs/$label.exit && ! -e $art/$label ]] || exit 1
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
pid=$(cat "$logs/$full.pid")
[[ $pid =~ ^[0-9]+$ ]] || exit 1
printf '[%s] Waiting for %s\n' "$(date -u +%FT%TZ)" "$full"
while [[ ! -f $logs/$full.exit ]]; do
    kill -0 "$pid" || { echo 'Build stopped without exit status'; exit 1; }
    sleep 15
done
[[ $(cat "$logs/$full.exit") == 0 ]] || { echo 'Full build failed; no artifact approval'; exit 1; }
exec 9>"$logs/build.lock"
flock -w 30 9 || { echo 'Unexpected active build; stopping checks'; exit 1; }
mkdir "$art/$label"
archive="$top/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip"
python3 "$port/tools/check-target-files.py" --top "$top" --archive "$archive" \
    --snapshot "$port/snapshots/$snapshot" --source-audit "$art/$full/source-audit-after.json" \
    --build-exit "$logs/$full.exit" --report "$art/$label/geometry-layout.json"
sha=$(python3 - "$art/$label/geometry-layout.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['artifact_checks_passed'] and r['ota_layout']['physical_non_ab']
assert not r['flash_ready']
print(r['archive_sha256'])
PY
)
[[ $sha =~ ^[0-9a-f]{64}$ ]] || exit 1
saved="$art/diagnostic-$full"
[[ ! -e $saved ]] || exit 1
mkdir "$saved"
cp --reflink=auto "$archive" "$saved/lineage_gta3xlwifi-target_files.zip"
sha256sum "$saved/lineage_gta3xlwifi-target_files.zip" > "$saved/SHA256SUMS"
[[ $(cut -d' ' -f1 "$saved/SHA256SUMS") == "$sha" ]] || exit 1
cp "$art/$full/source-audit-after.json" "$saved/source-audit-after.json"
printf '%s\n' 'DIAGNOSTIC ONLY. Strict vendor policy, kernel/network and Android17 recovery/installer gates remain. NOT FOR FLASHING.' > "$saved/NOT_READY_FOR_FLASHING.txt"
python3 "$port/tools/check-packaged-vendor-vintf.py" --top "$top" \
    --archive "$saved/lineage_gta3xlwifi-target_files.zip" --expected-archive-sha256 "$sha" \
    --vendor "$art/vendor-check-20261101-01/vendor" \
    --kernel-config /srv/android/artifacts/kernel-dt2w/kernel.config --output "$art/$label/offline-vintf"
printf '[%s] Offline artifact checks completed; NOT flash approval\n' "$(date -u +%FT%TZ)"
