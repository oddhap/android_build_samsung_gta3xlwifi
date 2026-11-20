#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Resume snapshot31 after runtime31-orchestrator-20261120-06 completed policy,
# strict checks, queries, labels, vendor composition and OTA staging.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
grep -q '^PASS staged snapshot31 ota:' "$L/runtime31-orchestrator-20261120-06.log"
[[ ! -e $(dirname $P)/../../src/lineage-24.0-arm64/device/samsung/gta3xlwifi/prebuilt/vendor.img.runtime31.tmp ]]
[[ $(cat "$L/firmware-policy-strict-20261120-03.exit") == 0 ]]
python3 -c 'import json,sys;[(lambda r:None if r["passed"] else sys.exit(1))(json.load(open(f))) for f in sys.argv[1:]]' \
  "$A/firmware-built-access-20261120-02/report.json" "$A/firmware-built-labels-20261120-02/report.json" \
  "$A/firmware-policy-vendor-20261120-01/report.json" "$A/runtime31-ota-selection-20261120-03/vendor-delta.json"
python3 "$P/tools/select-runtime31-inputs24.py"
bash "$P/tools/build-runtime31-product24.sh" runtime31-product-build-20261120-01 "$A/runtime31-inputs-20261120-01/report.json"
bash "$P/tools/run-runtime31-package24.sh"
