#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Offline metadata proposal; no TOP, images, cache hashes or devices modified.
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=${1:?Usage: check-platform-policy-port.sh NEW_LABEL}
mode=${2:-legacy-attributes}
[[ $mode == legacy-attributes || $mode == current-attributes || $mode == current-platform-memberships ]] || exit 2
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$logs/build.lock"
flock -n 9 || exit 1
out="$artifacts/$label"
[[ ! -e $out && ! -e $logs/$label.exit ]] || exit 1
mkdir "$out"
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
mkdir "$out/tools"
for tool in audit-port.py stage-platform-policy-port.py stage-vendor-platform-memberships.py stage-vendor-uwb-namespace.py check-vendor-policy.py check-platform-policy-port.sh; do
  cp "$port/tools/$tool" "$out/tools/"
done
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-before.json"
args=()
if [[ $mode != legacy-attributes ]]; then
  args=(--current-platform-report "$artifacts/vendor-policy-tightening-20261105-01/strict/report.json")
fi
metadata="$out/metadata"
[[ $mode != current-platform-memberships ]] || metadata="$out/platform-metadata"
python3 "$port/tools/stage-platform-policy-port.py" --top "$top" \
  --vendor "$artifacts/vendor-policy-tightening-20261105-01/metadata/vendor" --output "$metadata" "${args[@]}"
if [[ $mode == current-platform-memberships ]]; then
  python3 "$port/tools/stage-vendor-platform-memberships.py" --top "$top" \
    --vendor "$metadata/vendor" --output "$out/metadata" \
    --current-report "$artifacts/vendor-policy-tightening-20261105-01/strict/report.json"
fi
set +e
python3 "$port/tools/check-vendor-policy.py" --top "$top" --vendor "$out/metadata/vendor" \
  --out-dir out-policy-user-20261101-01 --output "$out/strict"
checker=$?
set -e
printf '%s\n' "$checker" > "$out/strict-checker.exit"
[[ $checker == 0 || $checker == 1 ]] || exit "$checker"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-after.json"
echo 'Experiment completed; inspect strict/report.json for the security result.'
