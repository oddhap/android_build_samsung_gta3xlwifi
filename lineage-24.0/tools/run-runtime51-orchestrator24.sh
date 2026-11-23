#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 51: snapshot50 + power-boost backend that suspends and retries (1-60 s backoff)
# after a control open/write failure instead of staying disabled until reboot; the
# reason is logged to the main and system buffers. Stage, rebind unchanged inputs,
# full build with power host tests, package checks, test OTA, then owner-approved
# release signing (release-20261123-01). Every step stops the chain.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime50-ota-checks-20261122-01.exit") == 0 ]]
[[ $(cat "$L/release-20261122-04-orchestrator.exit") == 0 ]]
test -f "$A/runtime50-ota-build-20261122-01/target-files.zip"
flock -n "$L/build.lock" bash -c 'set -e; source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime51-source24.py"
python3 "$P/tools/select-runtime51-inputs24.py"
bash "$P/tools/build-runtime51-product24.sh" runtime51-product-build-20261123-01 "$A/runtime51-inputs-20261123-01/report.json"
bash "$P/tools/run-runtime51-package24.sh"
[[ $(cat "$L/runtime51-package-workflow-20261123-01.exit") == 0 ]]
[[ $(cat "$L/runtime51-ota-checks-20261123-01.exit") == 0 ]]
bash "$P/tools/run-release-ota24.sh" release-20261123-01 runtime51-ota-build-20261123-01
[[ $(cat "$L/release-20261123-01-orchestrator.exit") == 0 ]]
