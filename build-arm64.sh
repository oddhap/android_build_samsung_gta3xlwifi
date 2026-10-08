#!/usr/bin/env bash
set -eo pipefail
top=/srv/android/src/lineage-21.0-arm64
port=/srv/android/ports/lineage-21-arm64/lineage-21
test -f /srv/android/artifacts/lineage-21-arm64/SOURCE_SYNC_COMPLETE
test -f /srv/android/artifacts/lineage-21-arm64/vendor-image-report.json
exec 9>/srv/android/logs/lineage-21-arm64/build.lock
flock -n 9 || { echo 'Another ARM64 build is active.' >&2; exit 1; }
test "$(df --output=avail -B1 /srv/android | tail -1)" -ge 53687091200 || { echo 'Less than 50 GiB free.' >&2; exit 1; }
cd "$top"
export OUT_DIR=out USE_CCACHE=1 CCACHE_EXEC=/usr/bin/ccache CCACHE_DIR=/srv/android/ccache
if [[ ! -f "$port/build-number-arm64" ]]; then
    date +%s > "$port/build-datetime-arm64"
    printf 'gta3xlwifi.arm64.%s\n' "$(date -u +%Y%m%d.%H%M%S)" > "$port/build-number-arm64"
fi
export BUILD_DATETIME=$(cat "$port/build-datetime-arm64")
export BUILD_NUMBER=$(cat "$port/build-number-arm64")
source build/envsetup.sh
lunch lineage_gta3xlwifi-ap2a-userdebug
if [[ $# == 0 ]]; then set -- target-files-package otatools; fi
m -j"${LINEAGE_BUILD_JOBS:-24}" "$@"
