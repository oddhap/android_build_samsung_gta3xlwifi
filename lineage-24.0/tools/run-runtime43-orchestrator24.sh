#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 43: snapshot42 with gate-split via HOLD argument (build 42's new ioctl number
# was denied by netd's SELinux xperm list). Policy and vendor unchanged. Every step stops the chain on failure.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
T=/srv/android/src/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime42-ota-checks-20261121-01.exit") == 0 ]]
[[ $(cat "$L/kernel-gate-split-build-20261121-02.exit") == 0 ]]
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261121-42" "$A/runtime43-orchestrator-source-before.json"
python3 "$P/tools/select-runtime43-inputs24.py"
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime43-source24.py"
flock -n "$L/build.lock" python3 "$P/tools/rebind-runtime43-touch-kernel24.py" runtime43-touch-kernel-rebind-20261121-01
bash "$P/tools/build-runtime43-product24.sh" runtime43-product-build-20261121-01 "$A/runtime43-inputs-20261121-02/report.json"
bash "$P/tools/run-runtime43-package24.sh"
