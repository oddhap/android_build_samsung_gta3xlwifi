#!/usr/bin/env bash
set -euo pipefail
p=/srv/android/ports/lineage-24.0-arm64
a=/srv/android/artifacts/lineage-24.0-arm64
l=/srv/android/logs/lineage-24.0-arm64
s=$p/active-stats-owner24-20261114-01
label=active-stats-validation-20261114-01
exec >"$l/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$l/$label.exit"; date -u' EXIT
# Each child owns the common lock; this sequential parent MUST NOT hold it.
bash "$p/lineage-24.0/experiments/kernel-active-stats-20261114-01/build-kernel.sh"
flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/test-controller-startup24.py" --source "$s" --android-source /srv/android/src/lineage-24.0-arm64 --runtime-source "$p/runtime-owner24-20261114-01" --guard-source "$p/controllers-guard24-20261106-01" --output "$a/active-stats-startup-host-20261114-01"
flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/test-controllers-guard24.py" --source "$s/Controllers.cpp" --reference /srv/android/src/lineage-24.0-arm64/system/netd/server/Controllers.cpp --output "$a/active-stats-guard-host-20261114-01"
flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/test-packet-stats-transport24.py" --source "$s" --reference-host "$a/loopback-event-transport-host-20261108-02" --output "$a/active-stats-packet-transport-host-20261114-01"
flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/test-runtime-transport24.py" --source "$s" --reference-host "$a/loopback-event-transport-host-20261108-02" --output "$a/active-stats-runtime-transport-host-20261114-01"
python3 "$p/lineage-24.0/tools/compile-active-stats-owner24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$s" --snapshot "$p/lineage-24.0/snapshots/port-20261106-04" --host-report "$a/active-stats-owner-host-20261114-02/report.json" --factory-report "$a/bandwidth-factory-host-20261113-01/report.json" --regression-report "$a/active-stats-owner-host-20261114-02/report.json" --transport-report "$a/active-stats-packet-transport-host-20261114-01/report.json" --runtime-transport-report "$a/active-stats-runtime-transport-host-20261114-01/report.json" --conversion-report "$a/permission-bootstrap-host-20261113-02/report.json" --kernel "$p/kernel-active-stats-20261114-01/src" --startup-report "$a/active-stats-startup-host-20261114-01/report.json" --guard-report "$a/active-stats-guard-host-20261114-01/report.json" --output "$a/active-stats-owner-native-20261114-01"
