#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime38-package-workflow-20261121-02
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime38-product-build-20261121-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime38-product-build-20261121-01.exit") == 0 ]]
# Snapshot32 changes no proof source; reuse the snapshot31 rebound host proofs.
test -f /srv/android/artifacts/lineage-24.0-arm64/aconfig-cache-host-runtime31-20261120-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime31-host-proof-rebind-20261120-02/report.json
# Snapshot38 changes device.mk-free sources only (BoardConfig.mk, mkbootimg.mk,
# releasetools.py): reuse the snapshot35 device.mk rebind. BoardConfig.mk is
# bound by the mapper and touch proofs; rebind only the inserted
# BOOT_SECURITY_PATCH block. Product checks re-verify every bound hash.
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime35-devicemk-rebind-20261120-01/report.json
python3 "$P/tools/rebind-runtime38-boardconfig24.py" runtime38-boardconfig-rebind-20261121-02
bash "$P/tools/check-runtime38-product24.sh" runtime38-product-checks-20261121-02
bash "$P/tools/check-runtime38-vintf24.sh" runtime38-vintf-20261121-01
bash "$P/tools/build-runtime38-test-ota24.sh" runtime38-ota-build-20261121-01
bash "$P/tools/check-runtime38-ota24.sh" runtime38-ota-checks-20261121-01
