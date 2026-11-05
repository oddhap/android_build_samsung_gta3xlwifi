#!/usr/bin/env bash
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=vendor-policy-tightening-20261105-01
art=/srv/android/artifacts/lineage-24.0-arm64/$label
exec 9>"$logs/build.lock"
flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; exit "$result"' EXIT
test ! -e "$art"
mkdir "$art"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$art/source-before.json"
python3 "$port/tools/stage-vendor-policy-tightening.py" --top "$top" \
 --vendor /srv/android/artifacts/lineage-24.0-arm64/vendor-check-20261101-01/vendor --output "$art/metadata"
set +e
python3 "$port/tools/check-vendor-policy.py" --top "$top" --vendor "$art/metadata/vendor" \
 --out-dir out-policy-user-20261101-01 --output "$art/strict"
rc=$?
set -e
printf '%s\n' "$rc" >"$art/strict-checker.exit"
# Keep failure. This experiment does not override the strict result.
test "$rc" = 1
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$art/source-after.json"
