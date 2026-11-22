#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 44: snapshot43 + OTA updates via the built-in LineageOS Updater (lineage.updater.uri,
# addon.d backup/restore with vendor/product write-protected) + TWRP 33875693 identity.
# Policy, vendor and kernel unchanged. Every step stops the chain on failure.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
T=/srv/android/src/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime43-ota-checks-20261121-01.exit") == 0 ]]
echo '33875693066aeb5e9f27bc2d469c3052b438552395cb476ed0d8340348765f05  '"$A"'/runtime44-recovery-images-20261121-01/recovery-fstab-abgr-partition.img' | sha256sum -c -
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261121-43" "$A/runtime44-orchestrator-source-before.json"
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime44-source24.py"
flock -n "$L/build.lock" python3 "$P/tools/rebind-runtime44-devicemk24.py" runtime44-devicemk-rebind-20261121-01
flock -n "$L/build.lock" python3 "$P/tools/test-runtime44-recovery-identity24.py" runtime44-recovery-identity-host-20261121-01
bash "$P/tools/build-runtime44-product24.sh" runtime44-product-build-20261121-01 "$A/runtime44-inputs-20261121-01/report.json"
bash "$P/tools/run-runtime44-package24.sh"
