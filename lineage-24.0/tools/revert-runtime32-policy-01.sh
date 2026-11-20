#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Return the checkout exactly to port-20261120-31 after a failed snapshot32
# policy step, keeping the failed snapshot as evidence.
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
S=$P/snapshots/port-20261120-32-policy
W=$A/runtime32-policy-selection-20261120-01/originals
python3 "$P/tools/audit-port.py" "$T" "$S" "$O/source-before.json"
for f in gta3xlwifi_ion.te gta3xlwifi_firmware.te; do
  cp "$W/$f" "$T/device/samsung/gta3xlwifi/sepolicy/private/$f"
done
[[ ! -e $P/snapshots/$failed ]]
mv "$S" "$P/snapshots/$failed"
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261120-31" "$O/source-after.json"
echo 'PASS checkout returned to port-20261120-31'
