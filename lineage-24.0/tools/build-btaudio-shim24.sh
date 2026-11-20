#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Place the staged Bluetooth audio shim in the device tree and build only it.
# No product, OTA or device operations. Snapshot capture happens separately.
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
staging=${2:?staging dir}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$L/build.lock"; flock -n 9 || exit 75
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
D=$T/device/samsung/gta3xlwifi/btaudio
python3 "$ports/lineage-24.0/tools/audit-port.py" "$T" "$ports/lineage-24.0/snapshots/port-20261120-33" "$O/source-before.json" || true
rm -rf "$D"
cp -r "$staging/btaudio" "$D"
git -C "$T/device/samsung/gta3xlwifi" add -N btaudio
cp "$staging/report.json" "$O/staging-report.json"
source "$ports/env.sh"
cd "$T"
source build/envsetup.sh
lunch lineage_gta3xlwifi aosp_current userdebug
m gta3xlwifi_btaudio_shim
so=$(find out/target/product/gta3xlwifi/vendor/lib/hw -name audio.bluetooth.exynos7904.so -newer "$O/staging-report.json" | head -1)
[[ -n $so ]]
cp "$so" "$O/audio.bluetooth.exynos7904.so"
readelf -d "$O/audio.bluetooth.exynos7904.so" | grep NEEDED >"$O/needed.txt"
file "$O/audio.bluetooth.exynos7904.so" >"$O/file.txt"
sha256sum "$O/audio.bluetooth.exynos7904.so" >"$O/SHA256SUMS"
cat "$O/file.txt" "$O/needed.txt"
