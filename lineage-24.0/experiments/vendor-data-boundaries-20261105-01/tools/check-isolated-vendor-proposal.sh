#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Serial offline policy proposals, with exact source audits and immutable labels.
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=${1:?Usage: check-isolated-vendor-proposal.sh NEW_LABEL STAGER BASELINE_REPORT}
stager=${2:?Missing stager}
baseline=${3:?Missing baseline}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
case "$stager" in stage-sandbox-file-access.py|stage-asec-clients.py|stage-vendor-private-property-owners.py|stage-property-writer-tightening.py|stage-legacy-bpf-policy.py|stage-legacy-wireless-ioctl.py|stage-legacy-domain-access.py|stage-vendor-data-boundaries.py) ;; *) exit 2 ;; esac
[[ $baseline == "$artifacts/"*/strict/report.json && -f $baseline ]] || exit 2
exec 9>"$logs/build.lock"
flock -n 9 || exit 1
out="$artifacts/$label"
[[ ! -e $out && ! -e $logs/$label.exit ]] || exit 1
mkdir "$out"
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
mkdir "$out/tools"
for tool in audit-port.py "$stager" replay-strict-vendor-cil.py policy-diagnostics.py stage-vendor-uwb-namespace.py stage-platform-policy-port.py check-isolated-vendor-proposal.sh; do
  cp "$port/tools/$tool" "$out/tools/"
done
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-before.json"
python3 "$port/tools/$stager" --baseline "$baseline" --output "$out/metadata"
extra=()
if [[ -f $out/metadata/plat_sepolicy.cil ]]; then
  extra=(--platform-cil "$out/metadata/plat_sepolicy.cil")
fi
python3 "$port/tools/replay-strict-vendor-cil.py" --baseline "$baseline" --vendor-cil "$out/metadata/vendor_sepolicy.cil" --output "$out/strict" "${extra[@]}"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-after.json"
echo 'Experiment complete. Strict compiler result remains authoritative; runner0 is not security approval.'
