#!/usr/bin/env bash
set -euo pipefail
p=/srv/android/ports/lineage-24.0-arm64
a=/srv/android/artifacts/lineage-24.0-arm64
l=/srv/android/logs/lineage-24.0-arm64
s=$p/runtime-owner24-20261114-01
label=runtime-native-validation-20261114-01
exec >"$l/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$l/$label.exit"; date -u' EXIT
flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/test-packet-stats-transport24.py" --source "$s" --reference-host "$a/loopback-event-transport-host-20261108-02" --output "$a/runtime-packet-transport-host-20261114-01"
python3 "$p/lineage-24.0/tools/compile-runtime-owner24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$s" --snapshot "$p/lineage-24.0/snapshots/port-20261106-04" --host-report "$a/runtime-owner-host-20261114-06/report.json" --factory-report "$a/bandwidth-factory-host-20261113-01/report.json" --regression-report "$a/runtime-owner-host-20261114-06/report.json" --transport-report "$a/runtime-packet-transport-host-20261114-01/report.json" --runtime-transport-report "$a/runtime-transport-host-20261114-02/report.json" --conversion-report "$a/permission-bootstrap-host-20261113-02/report.json" --kernel "$p/kernel-runtime-policy-20261113-02/src" --output "$a/runtime-owner-native-20261114-01"
