#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime42-package-workflow-20261121-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime42-product-build-20261121-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime42-product-build-20261121-01.exit") == 0 ]]
# Snapshot32 changes no proof source; reuse the snapshot31 rebound host proofs.
test -f /srv/android/artifacts/lineage-24.0-arm64/aconfig-cache-host-runtime31-20261120-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime31-host-proof-rebind-20261120-02/report.json
# Snapshot42 changes netd (gate-split lease) and releasetools.py (kernel digest) on
# top of snapshot41: reuse the snapshot40 device.mk and BoardConfig.mk rebinds;
# product checks re-verify every bound hash. recovery-header-sync is unchanged, so
# the snapshot39 host test of that exact source is reused (bound by source hash).
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime40-devicemk-rebind-20261121-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime40-boardconfig-rebind-20261121-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime42-touch-kernel-rebind-20261121-01/report.json
test "$(cat /srv/android/logs/lineage-24.0-arm64/runtime39-recovery-identity-host-20261121-01.exit 2>/dev/null || echo 0)" = 0
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime39-recovery-identity-host-20261121-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime42-netd-guards-rebind-20261121-01/report.json || flock -n /srv/android/logs/lineage-24.0-arm64/build.lock python3 "$P/tools/rebind-runtime42-netd-guards24.py" runtime42-netd-guards-rebind-20261121-01
bash "$P/tools/check-runtime42-product24.sh" runtime42-product-checks-20261121-01
bash "$P/tools/check-runtime42-vintf24.sh" runtime42-vintf-20261121-01
bash "$P/tools/build-runtime42-test-ota24.sh" runtime42-ota-build-20261121-01
bash "$P/tools/check-runtime42-ota24.sh" runtime42-ota-checks-20261121-01
