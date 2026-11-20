#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue checks/OTA only after the complete product after-audit succeeds.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=runtime33-package-workflow-20261120-02
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
while [[ ! -f $L/runtime33-product-build-20261120-02.exit ]]; do sleep 5; done
[[ $(cat "$L/runtime33-product-build-20261120-02.exit") == 0 ]]
# Snapshot32 changes no proof source; reuse the snapshot31 rebound host proofs.
test -f /srv/android/artifacts/lineage-24.0-arm64/aconfig-cache-host-runtime31-20261120-01/report.json
test -f /srv/android/artifacts/lineage-24.0-arm64/runtime31-host-proof-rebind-20261120-02/report.json
bash "$P/tools/check-runtime33-product24.sh" runtime33-product-checks-20261120-02
bash "$P/tools/check-runtime33-vintf24.sh" runtime33-vintf-20261120-01
bash "$P/tools/build-runtime33-test-ota24.sh" runtime33-ota-build-20261120-01
bash "$P/tools/check-runtime33-ota24.sh" runtime33-ota-checks-20261120-01
