#!/bin/bash
# Keep keys outside Git. Reuse them for every subsequent signed update.
set -eo pipefail
tools_dir=$(cd -- "$(dirname -- "$0")" && pwd)
bash "$tools_dir/build-rom.sh" target-files-package otatools
python3 "$tools_dir/sign-release.py" \
    /srv/android/src/lineage-21.0/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
