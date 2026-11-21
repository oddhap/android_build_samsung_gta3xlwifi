#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime37-package-workflow-20261120-01
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime37-product-build-20261120-01.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime37-product-build-20261120-01.exit") == 0 ]]
# Snapshot32 changes no proof source; reuse the snapshot31 rebound host proofs.
test -f /srv/android/artifacts/lineage-24.0-arm64/aconfig-cache-host-runtime31-20261120-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime31-host-proof-rebind-20261120-02/report.json
# Snapshot37 changes only iptables/libxtables, FileIntegrity, libcutils ashmem
# and init mount_handler (no proof-bound source): reuse the snapshot35 device.mk
# rebind; product checks re-verify every bound hash.
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime35-devicemk-rebind-20261120-01/report.json
bash "$P/tools/check-runtime37-product24.sh" runtime37-product-checks-20261120-01
bash "$P/tools/check-runtime37-vintf24.sh" runtime37-vintf-20261120-01
bash "$P/tools/build-runtime37-test-ota24.sh" runtime37-ota-build-20261120-01
bash "$P/tools/check-runtime37-ota24.sh" runtime37-ota-checks-20261120-01
