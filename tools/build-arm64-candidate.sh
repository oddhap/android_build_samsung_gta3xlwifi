#!/usr/bin/env bash
set -euo pipefail
port=/srv/android/ports/lineage-21-arm64
logs=/srv/android/logs/lineage-21-arm64
test -f /srv/android/artifacts/lineage-21-arm64/SOURCE_SYNC_COMPLETE
rm -f "$logs/targeted-build.exit" "$logs/full-build.exit"
# Keep the two stages sequential; both use the separate ARM64 OUT_DIR.
set +e
bash "$port/build-arm64.sh" init linker libEGL libnativewindow \
    libaudiohal libaudiohal@4.0 libprocessgroup libprocessgroup_setup \
    libgpuwork libmeminfo libfs_mgr libfs_mgr_binder libandroid_servers \
    gta3xlwifi_recovery_header_sync gta3xlwifi_abi_probe64 gta3xlwifi_abi_probe32 \
    > "$logs/targeted-build.log" 2>&1
result=$?
printf '%s\n' "$result" > "$logs/targeted-build.exit"
set -e
if [[ "$result" != 0 ]]; then tail -n 80 "$logs/targeted-build.log"; exit "$result"; fi
python3 "$port/lineage-21/tools/verify-targeted-arm64.py"
set +e
bash "$port/build-arm64.sh" target-files-package otatools > "$logs/full-build.log" 2>&1
result=$?
printf '%s\n' "$result" > "$logs/full-build.exit"
set -e
tail -n 80 "$logs/full-build.log"
exit "$result"
