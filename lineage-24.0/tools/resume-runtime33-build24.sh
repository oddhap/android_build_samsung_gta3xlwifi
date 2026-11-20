#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 33 resume: product-checks-01 stopped on the deliberate releasetools
# kernel guard. Stage snapshot33 (guard -> audited new kernel), rebuild, package.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime33-product-build-20261120-01.exit") == 0 ]]
[[ $(cat "$L/runtime33-product-checks-20261120-01.exit") == 1 ]]
grep -q 'Test OTA kernel differs from the audited private networking kernel' "$L/runtime33-product-checks-20261120-01.log"
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime33-source24.py"
bash "$P/tools/build-runtime33-product24.sh" runtime33-product-build-20261120-02 "$A/runtime33-inputs-20261120-02/report.json"
bash "$P/tools/run-runtime33-package24.sh"
