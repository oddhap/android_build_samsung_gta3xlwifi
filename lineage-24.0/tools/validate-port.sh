#!/usr/bin/env bash
# Apply only the pinned active port. No kernel experiments, OTA or device I/O.
set -eo pipefail
export PATH="$HOME/bin:$PATH"
port=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
snapshot="$port/lineage-24.0/snapshots/port-20261101"
exec 8>"$logs/build.lock"
flock -n 8 || exit 1
trap 'rc=$?; echo "$rc" > "$logs/port-validation.exit"' EXIT
source "$port/env.sh"
python3 "$port/lineage-24.0/tools/apply-port.py" "$PWD" "$snapshot"
# audit-port requires a manifest corresponding to the complete synced checkout.
mkdir -p "$artifacts/port-20261101"
cp "$snapshot/source-lock.json" "$artifacts/port-20261101/"
cp -R "$snapshot/patches" "$artifacts/port-20261101/"
cp "$artifacts/platform-manifest.xml" "$artifacts/port-20261101/port-manifest.xml"
python3 "$port/lineage-24.0/tools/audit-port.py" "$PWD" "$artifacts/port-20261101" "$artifacts/port-audit.json"
python3 "$port/lineage-24.0/tools/test-legacy-processgroups.py" "$PWD"
python3 "$port/lineage-24.0/tools/test-spawn-cloexec.py" "$PWD/bionic/libc/bionic/spawn.cpp"
source build/envsetup.sh
lunch lineage_gta3xlwifi aosp_current userdebug
# Dump configuration before any compilation. Full ROM/security/runtime gates
# remain separate; a successful lunch is not an Android 17 compatibility pass.
build/soong/soong_ui.bash --dumpvars-mode --vars='PLATFORM_VERSION PLATFORM_SDK_VERSION TARGET_ARCH TARGET_2ND_ARCH TARGET_PRODUCT TARGET_RELEASE' > "$artifacts/product-config.txt"
date -u +%FT%TZ > "$artifacts/PORT_SOURCE_VALIDATED"
