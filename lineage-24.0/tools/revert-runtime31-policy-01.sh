#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Return the checkout exactly to port-20261120-31-sync after a failed snapshot31
# policy step, keeping the failed snapshot as evidence.
# 01: vendor_firmware_file is vendor-only (unnameable by platform policy).
# 02: hal_codec2_server also contains platform mediaswcodec; use hal_omx_server.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?revert label}
reason=${2:?failed step label}
failed=${3:?failed snapshot name}
exec 9>"$L/build.lock"; flock -n 9 || exit 75
[[ ! -e $L/$label.exit ]] || exit 2
O=$A/$label; mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
[[ -f "$L/$reason.exit" ]]
echo "Reverting because of $reason"
S=$P/snapshots/port-20261120-31-policy
python3 "$P/tools/audit-port.py" "$T" "$S" "$O/source-before.json"
cd "$T"
git -C packages/modules/NetworkStack apply --reverse "$S/patches/packages_modules_NetworkStack.patch"
git -C packages/modules/NetworkStack reset -q
[[ -z $(git -C packages/modules/NetworkStack status --porcelain --untracked-files=normal) ]]
git -C device/samsung/gta3xlwifi rm -q --cached sepolicy/private/gta3xlwifi_firmware.te
rm device/samsung/gta3xlwifi/sepolicy/private/gta3xlwifi_firmware.te
[[ ! -e $P/snapshots/$failed ]]
mv "$S" "$P/snapshots/$failed"
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261120-31-sync" "$O/source-after.json"
echo 'PASS checkout returned to port-20261120-31-sync'
