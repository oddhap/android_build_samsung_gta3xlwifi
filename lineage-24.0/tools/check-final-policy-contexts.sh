#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
out="$art/$label"; [[ ! -e $out && ! -e $logs/$label.exit ]] || exit 1
mkdir "$out"
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
cp "$port/tools/check-policy-contexts.py" "$out/runner.py"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-before.json"
for profile in production userdebug; do
 if [[ $profile == production ]]; then policy="$art/vendor-app-data-types-20261105-02/strict/strict.policy"; buildout=out-policy-user-20261101-01; else policy="$art/staged-debug-policy-20261105-04/strict/strict.policy"; buildout=out; fi
 python3 "$port/tools/check-policy-contexts.py" --top "$top" --out-dir "$buildout" --vendor "$art/staged-debug-policy-20261105-04/metadata/vendor" --policy "$policy" --strict-report "${policy%/*}/report.json" --output "$out/$profile"
done
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-after.json"
