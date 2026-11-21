#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime41-package-workflow-20261121-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime41-product-build-20261121-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime41-product-build-20261121-01.exit") == 0 ]]
# Snapshot32 changes no proof source; reuse the snapshot31 rebound host proofs.
test -f /srv/android/artifacts/lineage-24.0-arm64/aconfig-cache-host-runtime31-20261120-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime31-host-proof-rebind-20261120-02/report.json
# Snapshot41 changes only gta3xlwifi_ion.te (policy) and releasetools.py (vendor
# hash) on top of snapshot40: reuse the snapshot40 device.mk and BoardConfig.mk rebinds;
# product checks re-verify every bound hash. recovery-header-sync is unchanged, so
# the snapshot39 host test of that exact source is reused (bound by source hash).
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime40-devicemk-rebind-20261121-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime40-boardconfig-rebind-20261121-01/report.json
test "$(cat /srv/android/logs/lineage-24.0-arm64/runtime39-recovery-identity-host-20261121-01.exit 2>/dev/null || echo 0)" = 0
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime39-recovery-identity-host-20261121-01/report.json
bash "$P/tools/check-runtime41-product24.sh" runtime41-product-checks-20261121-01
bash "$P/tools/check-runtime41-vintf24.sh" runtime41-vintf-20261121-01
bash "$P/tools/build-runtime41-test-ota24.sh" runtime41-ota-build-20261121-01
bash "$P/tools/check-runtime41-ota24.sh" runtime41-ota-checks-20261121-01
