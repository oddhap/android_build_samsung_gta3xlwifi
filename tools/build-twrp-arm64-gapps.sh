#!/bin/bash
set -eo pipefail
cd /srv/android/src/twrp-12.1-pinfree
test "$(df --output=avail -B1 /srv/android | tail -1)" -ge 37580963840
python3 /srv/android/ports/twrp-pinfree/fix-twrp-pinfree.py "$PWD"
python3 /srv/android/ports/twrp-pinfree/fix-twrp-arm64-relink.py "$PWD"
export OUT_DIR=out-arm64-gapps USE_CCACHE=1 CCACHE_EXEC=/usr/bin/ccache CCACHE_DIR=/srv/android/ccache ALLOW_MISSING_DEPENDENCIES=true
source build/envsetup.sh
lunch twrp_gta3xlwifi-eng
m -j16 recoveryimage
