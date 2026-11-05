#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
base="$artifacts/legacy-policy-access-20261105-03"
label=${1:?Usage: check-vendor-property-owners.sh NEW_LABEL}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$logs/build.lock"
flock -n 9 || exit 1
out="$artifacts/$label"
[[ ! -e $out && ! -e $logs/$label.exit ]] || exit 1
mkdir "$out"
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
mkdir "$out/tools"
for tool in audit-port.py audit-vendor-property-owners.py stage-vendor-property-owners.py replay-strict-vendor-cil.py stage-vendor-uwb-namespace.py stage-platform-policy-port.py check-vendor-property-owners.sh; do
  cp "$port/tools/$tool" "$out/tools/"
done
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-before.json"
python3 "$port/tools/stage-vendor-property-owners.py" --audit "$base/property-ownership-audit.json" \
  --baseline "$base/strict/report.json" --output "$out/metadata"
python3 "$port/tools/replay-strict-vendor-cil.py" --baseline "$base/strict/report.json" \
  --vendor-cil "$out/metadata/vendor_sepolicy.cil" --output "$out/strict"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-after.json"
echo 'Experiment complete. Read strict/report.json; runner success is not policy approval.'
