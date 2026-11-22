#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=runtime45-package-workflow-20261121-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime45-product-build-20261121-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime45-product-build-20261121-01.exit") == 0 ]]
test -f $A/aconfig-cache-host-runtime31-20261120-01/report.json
test -f $A/runtime31-host-proof-rebind-20261120-02/report.json
# Snapshot45 changes only releasetools.py (chain walked by check-runtime45-bootspl/-updater).
# Snapshot44 changes device.mk (rebound: runtime44-devicemk-rebind), releasetools.py
# (edit chain walked by check-runtime44-bootspl, hook order by check-runtime44-updater)
# and recovery_header_sync.cpp (fresh host test runtime44-recovery-identity-host).
# BoardConfig, touch and netd sources are unchanged: reuse their snapshot40/43/42 rebinds;
# product checks re-verify every bound hash.
test -f $A/runtime40-boardconfig-rebind-20261121-01/report.json
test -f $A/runtime43-touch-kernel-rebind-20261121-01/report.json
test -f $A/runtime42-netd-guards-rebind-20261121-01/report.json
test -f $A/runtime44-devicemk-rebind-20261121-01/report.json
test "$(cat $L/runtime44-recovery-identity-host-20261121-01.exit 2>/dev/null || echo 0)" = 0
test -f $A/runtime44-recovery-identity-host-20261121-01/report.json
bash "$P/tools/check-runtime45-product24.sh" runtime45-product-checks-20261121-01
bash "$P/tools/check-runtime45-vintf24.sh" runtime45-vintf-20261121-01
bash "$P/tools/build-runtime45-test-ota24.sh" runtime45-ota-build-20261121-01
bash "$P/tools/check-runtime45-ota24.sh" runtime45-ota-checks-20261121-01
