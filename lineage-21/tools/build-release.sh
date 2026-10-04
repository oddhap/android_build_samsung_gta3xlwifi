#!/bin/bash
# Keep keys outside Git. Reuse them for every subsequent signed update.
set -eo pipefail
tools_dir=$(cd -- "$(dirname -- "$0")" && pwd)
# A release must have a new identity: PackageManager keys its parse cache on
# partition fingerprints, while packaged APK mtimes are reproducibly fixed.
port_dir=$(cd -- "$tools_dir/.." && pwd)
release_epoch=$(date +%s)
printf '%s\n' "$release_epoch" > "$port_dir/build-datetime"
printf 'gta3xlwifi.%s\n' "$(date -u -d "@$release_epoch" +%Y%m%d.%H%M%S)" > "$port_dir/build-number"
bash "$tools_dir/build-rom.sh" target-files-package otatools
python3 "$tools_dir/sign-release.py" \
    /srv/android/src/lineage-21.0/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
