#!/bin/bash
set -eo pipefail
port_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd /srv/android/src/lineage-21.0
export USE_CCACHE=1 CCACHE_EXEC=/usr/bin/ccache CCACHE_DIR=/srv/android/ccache
build_timestamp="$port_dir/build-datetime"
if [[ ! -f "$build_timestamp" ]]; then date +%s > "$build_timestamp"; fi
export BUILD_DATETIME=$(cat "$build_timestamp")
build_number="$port_dir/build-number"
if [[ ! -f "$build_number" ]]; then
    printf 'gta3xlwifi.%s\n' "$(date -u -d "@$BUILD_DATETIME" +%Y%m%d.%H%M%S)" > "$build_number"
fi
export BUILD_NUMBER=$(cat "$build_number")
source build/envsetup.sh
lunch lineage_gta3xlwifi-ap2a-userdebug
if [ "$#" -eq 0 ]; then set -- bacon; fi
m -j"${LINEAGE_BUILD_JOBS:-24}" "$@"
