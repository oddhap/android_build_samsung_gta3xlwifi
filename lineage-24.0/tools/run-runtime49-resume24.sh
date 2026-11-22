#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 49 resume after attempt a: product build passed, product checks stopped at a
# misnamed hwui check (check-runtime49-hwui -> check-runtime48-hwui). Attempt-a check,
# package-workflow and orchestrator logs/artifacts are kept as *-failed-a. Re-run the
# package workflow and release signing on the unchanged build.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime49-product-build-20261122-01.exit") == 0 ]]
[[ $(cat "$L/runtime49-product-checks-20261122-01-failed-a.exit") == 2 ]]
[[ ! -e $L/runtime49-product-checks-20261122-01.exit && ! -e $L/runtime49-package-workflow-20261122-01.exit ]]
python3 "$P/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$P/snapshots/port-20261122-49" /srv/android/artifacts/lineage-24.0-arm64/runtime49-resume-source-before.json
bash "$P/tools/run-runtime49-package24.sh"
[[ $(cat "$L/runtime49-package-workflow-20261122-01.exit") == 0 ]]
[[ $(cat "$L/runtime49-ota-checks-20261122-01.exit") == 0 ]]
bash "$P/tools/run-release-ota24.sh" release-20261122-03 runtime49-ota-build-20261122-01
[[ $(cat "$L/release-20261122-03-orchestrator.exit") == 0 ]]
