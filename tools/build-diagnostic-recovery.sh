#!/bin/bash
set -eo pipefail
cd /srv/android/src/lineage-19.1
task_init=device/samsung/gta3xlwifi/recovery/root/init.recovery.exynos7904.rc
mkdir -p /srv/android/artifacts/diagnostic-recovery
cp "$task_init" /srv/android/artifacts/diagnostic-recovery/init-original.rc
trap 'cp /srv/android/artifacts/diagnostic-recovery/init-original.rc "$task_init"' EXIT
cp /srv/android/init.recovery-diagnostic.exynos7904.rc "$task_init"
export USE_CCACHE=1
export CCACHE_EXEC=/usr/bin/ccache
export CCACHE_DIR=/srv/android/ccache
source build/envsetup.sh
lunch lineage_gta3xlwifi-userdebug
m -j16 recoveryimage
cp out/target/product/gta3xlwifi/recovery.img /srv/android/artifacts/diagnostic-recovery/recovery.img
