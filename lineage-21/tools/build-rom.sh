#!/bin/bash
set -eo pipefail
cd /srv/android/src/lineage-21.0
export USE_CCACHE=1 CCACHE_EXEC=/usr/bin/ccache CCACHE_DIR=/srv/android/ccache
build_timestamp=/srv/android/ports/lineage-21/build-datetime
if [[ ! -f "$build_timestamp" ]]; then date +%s > "$build_timestamp"; fi
export BUILD_DATETIME=$(cat "$build_timestamp")
source build/envsetup.sh
lunch lineage_gta3xlwifi-ap2a-userdebug
if [ "$#" -eq 0 ]; then set -- bacon; fi
m -j"${LINEAGE_BUILD_JOBS:-24}" "$@"
