#!/usr/bin/env bash
set -euo pipefail
p=/srv/android/ports/lineage-24.0-arm64
a=/srv/android/artifacts/lineage-24.0-arm64
l=/srv/android/logs/lineage-24.0-arm64
label=policy-client-validation-20261114-01
exec >"$l/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$l/$label.exit"; date -u' EXIT
python3 "$p/lineage-24.0/tools/compile-policy-client24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$p/policy-client24-20261114-02" --previous-source "$p/policy-frame24-20261114-01" --base-report "$a/held-provider-native-20261114-02/report.json" --snapshot "$p/lineage-24.0/snapshots/port-20261106-04" --output "$a/policy-client-native-20261114-03"
python3 "$p/lineage-24.0/tools/test-policy-java-client24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$p/policy-client24-20261114-02" --native-report "$a/policy-client-native-20261114-03/report.json" --output "$a/policy-client-java-host-20261114-01"
