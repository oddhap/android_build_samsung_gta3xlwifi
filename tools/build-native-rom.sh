#!/bin/bash
set -eo pipefail
cd /srv/android/src/lineage-19.1
python3 /srv/android/tools/apply-systemui-fix.py
python3 /srv/android/tools/apply-power-boost.py
export USE_CCACHE=1
export CCACHE_EXEC=/usr/bin/ccache
export CCACHE_DIR=/srv/android/ccache
export BUILD_DATETIME=$(date +%s)
source build/envsetup.sh
lunch lineage_gta3xlwifi-userdebug
if [ "$#" -eq 0 ]; then
    set -- bacon
fi
m -j16 "$@"
