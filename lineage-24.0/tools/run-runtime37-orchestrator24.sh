#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 37: installed snapshot36 + log-noise corrections with a clean cause
# (iptables revision warning, fs-verity on pre-R launch, memfd readlink in
# sandboxes, quiet dm probe). Policy, vendor, kernel unchanged from build 36.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime36-ota-checks-20261120-01.exit") == 0 ]]
flock -n "$L/build.lock" bash -c 'source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime37-source24.py"
bash "$P/tools/build-runtime37-product24.sh" runtime37-product-build-20261120-01 "$A/runtime37-inputs-20261120-01/report.json"
bash "$P/tools/run-runtime37-package24.sh"
