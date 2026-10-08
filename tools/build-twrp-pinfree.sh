#!/bin/bash
set -eo pipefail
cd /srv/android/src/twrp-12.1-pinfree
available=$(df --output=avail -B1 /srv/android | tail -1)
if (( available < 50 * 1024 * 1024 * 1024 )); then
    echo "Less than 50 GiB available; refusing build" >&2
    exit 1
fi
python3 /srv/android/ports/twrp-pinfree/fix-twrp-pinfree.py "$PWD"
export USE_CCACHE=1
export CCACHE_EXEC=/usr/bin/ccache
export CCACHE_DIR=/srv/android/ccache
export ALLOW_MISSING_DEPENDENCIES=true
source build/envsetup.sh
lunch twrp_gta3xlwifi-eng
m -j16 recoveryimage
