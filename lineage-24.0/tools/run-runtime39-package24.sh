#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime39-package-workflow-20261121-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime39-product-build-20261121-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime39-product-build-20261121-01.exit") == 0 ]]
# Snapshot32 changes no proof source; reuse the snapshot31 rebound host proofs.
test -f /srv/android/artifacts/lineage-24.0-arm64/aconfig-cache-host-runtime31-20261120-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime31-host-proof-rebind-20261120-02/report.json
# Snapshot39 changes only recovery-header-sync (no proof-bound source): reuse
# the snapshot35 device.mk and snapshot38 BoardConfig.mk rebinds; product checks
# re-verify every bound hash. Host-test the new preflight source first.
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime35-devicemk-rebind-20261120-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime38-boardconfig-rebind-20261121-02/report.json
python3 "$P/tools/test-runtime39-recovery-identity24.py" runtime39-recovery-identity-host-20261121-01
bash "$P/tools/check-runtime39-product24.sh" runtime39-product-checks-20261121-01
bash "$P/tools/check-runtime39-vintf24.sh" runtime39-vintf-20261121-01
bash "$P/tools/build-runtime39-test-ota24.sh" runtime39-ota-build-20261121-01
bash "$P/tools/check-runtime39-ota24.sh" runtime39-ota-checks-20261121-01
