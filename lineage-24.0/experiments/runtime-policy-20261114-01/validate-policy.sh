#!/usr/bin/env bash
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
integration=$ports/lineage-24.0
logs=/srv/android/logs/lineage-24.0-arm64
label=runtime-policy-20261114-01
art=/srv/android/artifacts/lineage-24.0-arm64
exec 9>"$logs/build.lock"
flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
finish(){ result=$?; trap - EXIT; if [[ -f $art/$label/source-before.json && ! -e $art/$label/source-after.json ]]; then python3 "$integration/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$integration/snapshots/port-20261106-04" "$art/$label/source-after.json" || result=1; fi; printf '%s\n' "$result" >"$logs/$label.exit"; date -u; exit "$result"; }
trap finish EXIT
mkdir "$art/$label"
python3 "$integration/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$integration/snapshots/port-20261106-04" "$art/$label/source-before.json"
for flavor in production debug; do
 base=$art/packet-stats-policy-$flavor-20261113-01/strict/report.json
 target=$art/runtime-policy-$flavor-20261114-01
 python3 "$integration/tools/stage-runtime-policy24.py" --baseline "$base" --kernel "$ports/kernel-runtime-policy-20261113-02/src" --output "$target/metadata"
 vendor=$(python3 -c 'import json,sys;from pathlib import Path;print(next(x["path"] for x in json.load(open(sys.argv[1]))["inputs"] if Path(x["path"]).name=="vendor_sepolicy.cil"))' "$base")
 python3 "$integration/tools/replay-strict-vendor-cil.py" --baseline "$base" --vendor-cil "$vendor" --platform-cil "$target/metadata/plat_sepolicy.cil" --output "$target/strict"
 python3 "$integration/tools/probe-runtime-policy24.py" --top /srv/android/src/lineage-24.0-arm64 --strict-report "$target/strict/report.json" --output "$target/probes"
done
python3 "$integration/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$integration/snapshots/port-20261106-04" "$art/$label/source-after.json"
