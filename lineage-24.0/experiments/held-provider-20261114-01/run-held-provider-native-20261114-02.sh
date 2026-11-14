#!/usr/bin/env bash
set -euo pipefail
p=/srv/android/ports/lineage-24.0-arm64
a=/srv/android/artifacts/lineage-24.0-arm64
l=/srv/android/logs/lineage-24.0-arm64
s=$p/held-provider24-20261114-01
label=held-provider-validation-20261114-02
exec >"$l/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$l/$label.exit"; date -u' EXIT
python3 "$p/lineage-24.0/tools/compile-held-provider24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$s" --snapshot "$p/lineage-24.0/snapshots/port-20261106-04" --host-report "$a/held-provider-owner-host-20261114-01/report.json" --factory-report "$a/bandwidth-factory-host-20261113-01/report.json" --regression-report "$a/held-provider-owner-host-20261114-01/report.json" --transport-report "$a/held-provider-packet-transport-host-20261114-01/report.json" --runtime-transport-report "$a/held-provider-runtime-transport-host-20261114-01/report.json" --conversion-report "$a/permission-bootstrap-host-20261113-02/report.json" --kernel "$p/kernel-active-stats-20261114-01/src" --startup-report "$a/held-provider-controller-startup-host-20261114-01/report.json" --guard-report "$a/held-provider-guard-host-20261114-01/report.json" --tagger-report "$a/held-provider-tagger-transport-host-20261114-01/report.json" --library-report "$a/held-provider-library-host-20261114-01/report.json" --adapter-report "$a/held-provider-startup-host-20261114-01/report.json" --contract-report "$a/tagging-contract-20261114-01/report.json" --output "$a/held-provider-native-20261114-02"
for flavor in production debug; do
 flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/probe-qtaguid-transport-policy.py" --top /srv/android/src/lineage-24.0-arm64 --strict-report "$a/runtime-policy-$flavor-20261114-01/strict/report.json" --output "$a/held-provider-qtaguid-policy-$flavor-20261114-01"
done
