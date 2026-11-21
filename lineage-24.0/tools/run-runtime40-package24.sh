#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime40-package-workflow-20261121-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime40-product-build-20261121-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime40-product-build-20261121-01.exit") == 0 ]]
# Snapshot32 changes no proof source; reuse the snapshot31 rebound host proofs.
test -f /srv/android/artifacts/lineage-24.0-arm64/aconfig-cache-host-runtime31-20261120-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime31-host-proof-rebind-20261120-02/report.json
# Snapshot40 changes only BoardConfig.mk, device.mk (product image) and the root
# fstab: use the new snapshot40 device.mk and BoardConfig.mk rebinds;
# product checks re-verify every bound hash. recovery-header-sync is unchanged, so
# the snapshot39 host test of that exact source is reused (bound by source hash).
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime40-devicemk-rebind-20261121-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime40-boardconfig-rebind-20261121-01/report.json
test "$(cat /srv/android/logs/lineage-24.0-arm64/runtime39-recovery-identity-host-20261121-01.exit 2>/dev/null || echo 0)" = 0
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime39-recovery-identity-host-20261121-01/report.json
bash "$P/tools/check-runtime40-product24.sh" runtime40-product-checks-20261121-01
bash "$P/tools/check-runtime40-vintf24.sh" runtime40-vintf-20261121-01
bash "$P/tools/build-runtime40-test-ota24.sh" runtime40-ota-build-20261121-01
bash "$P/tools/check-runtime40-ota24.sh" runtime40-ota-checks-20261121-01
