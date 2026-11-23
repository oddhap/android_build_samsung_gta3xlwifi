#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 50: snapshot49 + PRODUCT_ENABLE_UFFD_GC := false. The 4.4 kernel has no
# userfaultfd, so ART runs the concurrent-copying GC and rejected every boot image/odex
# dexpreopted for CMC (framework and apps ran interpreted/JIT: lag, SystemUI ANRs).
# Stage, rebind unchanged inputs, full build, package checks, test OTA, then
# owner-approved release signing (release-20261122-04). Every step stops the chain.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime49-ota-checks-20261122-01.exit") == 0 ]]
[[ $(cat "$L/release-20261122-03-orchestrator.exit") == 0 ]]
test -f "$A/runtime49-ota-build-20261122-01/target-files.zip"
flock -n "$L/build.lock" bash -c 'set -e; source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime50-source24.py"
python3 "$P/tools/select-runtime50-inputs24.py"
bash "$P/tools/build-runtime50-product24.sh" runtime50-product-build-20261122-01 "$A/runtime50-inputs-20261122-01/report.json"
bash "$P/tools/run-runtime50-package24.sh"
[[ $(cat "$L/runtime50-package-workflow-20261122-01.exit") == 0 ]]
[[ $(cat "$L/runtime50-ota-checks-20261122-01.exit") == 0 ]]
bash "$P/tools/run-release-ota24.sh" release-20261122-04 runtime50-ota-build-20261122-01
[[ $(cat "$L/release-20261122-04-orchestrator.exit") == 0 ]]
