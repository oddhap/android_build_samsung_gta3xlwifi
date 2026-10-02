#!/bin/bash
set -eo pipefail
cd /srv/android/src/twrp-12.1
python3 /srv/android/fix-twrp-relink-dependencies.py
python3 /srv/android/fix-twrp-fbe-startup.py
export USE_CCACHE=1
export CCACHE_EXEC=/usr/bin/ccache
export CCACHE_DIR=/srv/android/ccache
# Minimal TWRP manifest intentionally excludes Android/VTS test projects.
# Soong may ignore missing unused modules; Ninja still fails if recovery needs one.
export ALLOW_MISSING_DEPENDENCIES=true
source build/envsetup.sh
lunch twrp_gta3xlwifi-eng
m -j16 recoveryimage
