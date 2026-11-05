#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=${1:?Usage: check-staged-debug-policy.sh NEW_LABEL}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
production_report=${2:-$artifacts/legacy-property-views-20261105-01/strict/report.json}
[[ $production_report == "$artifacts/"*/strict/report.json && -f $production_report ]] || exit 2
exec 9>"$logs/build.lock"
flock -n 9 || exit 1
out="$artifacts/$label"
[[ ! -e $out && ! -e $logs/$label.exit ]] || exit 1
mkdir "$out"
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
mkdir "$out/tools"
for tool in audit-port.py stage-debug-policy-inputs.py check-vendor-policy.py stage-vendor-uwb-namespace.py stage-platform-policy-port.py check-staged-debug-policy.sh; do cp "$port/tools/$tool" "$out/tools/"; done
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-before.json"
python3 "$port/tools/stage-debug-policy-inputs.py" --production-report "$production_report" --output "$out/metadata"
python3 "$port/tools/check-vendor-policy.py" --top "$top" --out-dir out --vendor "$out/metadata/vendor" \
 --system-ext-cil "$out/metadata/system_ext_sepolicy.cil" --platform-cil "$out/metadata/plat_sepolicy.cil" --system-compat-cil "$out/metadata/30.0.compat.cil" --output "$out/strict"
"$top/out/host/linux-x86/bin/sepolicy-analyze" "$out/strict/strict.policy" permissive > "$out/permissive-domains.txt"
[[ ! -s $out/permissive-domains.txt ]] || { echo 'Unexpected permissive domain'; exit 1; }
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-after.json"
echo 'Strict staged userdebug policy passed, no permissive domains; not a boot/ROM approval.'
