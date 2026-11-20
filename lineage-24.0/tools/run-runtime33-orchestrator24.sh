#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 33: installed snapshot32 sources/policy/vendor + isolated netpolicy
# flush kernel. Every step stops the chain on failure.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
T=/srv/android/src/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime32-ota-checks-20261120-01.exit") == 0 ]]
[[ $(cat "$L/kernel-netpolicy-flush-build-20261120-01.exit") == 0 ]]
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261120-32" "$A/runtime33-orchestrator-source-before.json"
flock -n "$L/build.lock" python3 "$P/tools/rebind-runtime33-touch-kernel24.py" runtime33-touch-kernel-rebind-20261120-01
python3 "$P/tools/select-runtime33-inputs24.py"
bash "$P/tools/build-runtime33-product24.sh" runtime33-product-build-20261120-01 "$A/runtime33-inputs-20261120-01/report.json"
bash "$P/tools/run-runtime33-package24.sh"
