#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=${1:?Usage: check-legacy-policy-access.sh NEW_LABEL}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$logs/build.lock"
flock -n 9 || exit 1
out="$artifacts/$label"
[[ ! -e $out && ! -e $logs/$label.exit ]] || exit 1
mkdir "$out"
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
cp "$port/tools/check-legacy-policy-access.sh" "$out/runner.sh"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-before.json"
python3 "$port/tools/tighten-legacy-policy-access.py" \
  --baseline "$artifacts/platform-policy-port-20261105-03/strict/report.json" --output "$out/metadata"
mkdir "$out/strict"
cp "$out/metadata/strict/report.json" "$out/metadata/strict/strict.log" "$out/strict/"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-after.json"
echo 'Experiment complete. Read strict/report.json; runner success is not policy approval.'
